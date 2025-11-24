#!/usr/bin/env python3
"""
TCP Connection Viewer - GUI application for viewing and managing TCP connections.
Similar to TCPView for Windows but for macOS/Linux.
"""

import sys
import os
import subprocess
import threading
import time
from datetime import datetime
from typing import List, Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget, QMenu, QMessageBox, QPushButton,
    QHBoxLayout, QLabel, QHeaderView, QCheckBox, QLineEdit,
    QStyledItemDelegate, QStyleOptionButton, QStyle
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QObject, QEvent, QPoint, QRect
from PyQt6.QtGui import QAction, QFont, QColor, QMouseEvent, QGuiApplication, QPainter

# Import our existing killer module
from tcp_killer import _find_socket_fds, _shutdown_sockfd, ConnectionInfo


class ConnectionMonitor(QObject):
    """Worker thread for monitoring TCP connections."""
    
    connections_updated = pyqtSignal(list)
    error_occurred = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.running = False
        self.update_interval = 5000  # milliseconds
        
    def start_monitoring(self):
        """Start monitoring connections."""
        self.running = True
        while self.running:
            try:
                connections = self.get_all_connections()
                self.connections_updated.emit(connections)
            except Exception as e:
                self.error_occurred.emit(str(e))
            
            # Sleep in small intervals to allow quick stopping
            for _ in range(int(self.update_interval / 100)):
                if not self.running:
                    break
                time.sleep(0.1)
    
    def stop_monitoring(self):
        """Stop monitoring connections."""
        self.running = False
    
    def get_all_connections(self) -> List[ConnectionInfo]:
        """Get all TCP connections."""
        return _find_socket_fds()


class CloseButtonDelegate(QStyledItemDelegate):
    """Custom delegate to render close button in first column."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        
    def paint(self, painter, option, index):
        if index.column() == 0:  # First column
            # Draw the close button emoji
            painter.save()
            
            # Set up the text rect centered in the cell
            text_rect = option.rect
            painter.setPen(QColor(200, 50, 50))  # Red color for the X
            
            # Draw larger emoji-like X
            font = painter.font()
            font.setPointSize(14)
            painter.setFont(font)
            
            # Center the emoji in the cell
            painter.drawText(text_rect, Qt.AlignmentFlag.AlignCenter, "❌")
            
            painter.restore()
        else:
            super().paint(painter, option, index)
    
    def editorEvent(self, event, model, option, index):
        """Handle click events on the close button."""
        if index.column() == 0:  # First column
            if event.type() == QEvent.Type.MouseButtonRelease:
                if event.button() == Qt.MouseButton.LeftButton:
                    # Get the connection from the table
                    if hasattr(self.parent, 'handle_close_button_click'):
                        self.parent.handle_close_button_click(index.row())
                    return True
        return super().editorEvent(event, model, option, index)


class ConnectionTableWidget(QTableWidget):
    """Custom table widget for displaying TCP connections."""
    
    close_connection_requested = pyqtSignal(object)  # Signal to request connection close
    
    def __init__(self):
        super().__init__()
        self.setup_table()
        self.connections = []
        self.connection_map = {}  # Maps row to connection for proper sorting support
        self.process_name_cache = {}  # Cache for process names
        self.executable_path_cache = {}  # Cache for PID to executable path mapping
        self.codesign_flags_cache = {}  # Cache for executable path to codesign flags
        
        # Set custom delegate for close button
        self.close_delegate = CloseButtonDelegate(self)
        self.setItemDelegateForColumn(0, self.close_delegate)
    
    def get_executable_path(self, pid: int) -> Optional[str]:
        """Get the full executable path for a given PID."""
        # Check cache first
        if pid in self.executable_path_cache:
            return self.executable_path_cache[pid]
        
        try:
            # Try to get executable path using ps command
            result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "comm="],
                capture_output=True,
                text=True,
                timeout=0.5
            )
            if result.returncode == 0:
                exec_path = result.stdout.strip()
                # If it's not an absolute path, try to get the full path
                if not exec_path.startswith('/'):
                    # Try using lsof to get the full path
                    lsof_result = subprocess.run(
                        ["lsof", "-p", str(pid)],
                        capture_output=True,
                        text=True,
                        timeout=0.5
                    )
                    if lsof_result.returncode == 0:
                        # Look for the txt (program text) entry
                        for line in lsof_result.stdout.splitlines():
                            if "txt" in line:
                                parts = line.split()
                                if len(parts) >= 9:
                                    exec_path = parts[8]
                                    break
                
                self.executable_path_cache[pid] = exec_path
                return exec_path
        except Exception:
            pass
        
        self.executable_path_cache[pid] = None
        return None
    
    def get_codesign_flags(self, executable_path: str) -> str:
        """Get codesign flags for an executable."""
        # Check cache first
        if executable_path in self.codesign_flags_cache:
            return self.codesign_flags_cache[executable_path]
        
        flags = ""
        try:
            # Run codesign command
            result = subprocess.run(
                ["codesign", "-dv", executable_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=0.5
            )
            
            # Parse the output for flags (codesign outputs to stderr)
            for line in result.stderr.splitlines():
                if "CodeDirectory" in line and "flags=" in line:
                    # Extract flags from line like: CodeDirectory v=20400 size=490 flags=0x2(adhoc) hashes=9+3
                    import re
                    match = re.search(r'flags=([^\s]+)', line)
                    if match:
                        flags = match.group(1)
                        break
        except Exception as e:
            print(f"Error getting codesign flags for {executable_path}: {e}")
            pass
        
        # Cache the result
        self.codesign_flags_cache[executable_path] = flags
        return flags
    
    def get_process_flags(self, pid: int) -> str:
        """Get codesign flags for a process."""
        exec_path = self.get_executable_path(pid)
        if exec_path and exec_path.startswith('/'):
            return self.get_codesign_flags(exec_path)
        return ""
    
    def get_process_name(self, pid: int) -> str:
        """Get the process name for a given PID."""
        # Check cache first
        if pid in self.process_name_cache:
            return self.process_name_cache[pid]
        
        try:
            # Try to get process name using ps command
            result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "comm="],
                capture_output=True,
                text=True,
                timeout=0.5
            )
            if result.returncode == 0:
                # Get just the basename of the process
                process_name = result.stdout.strip()
                # Remove any path components
                process_name = os.path.basename(process_name)
                # Truncate if too long
                if len(process_name) > 15:
                    process_name = process_name[:12] + "..."
                self.process_name_cache[pid] = process_name
                return process_name
        except Exception:
            pass
        
        # Default if we can't get the name
        unknown = "unknown"
        self.process_name_cache[pid] = unknown
        return unknown
        
    def setup_table(self):
        """Set up the table columns and properties."""
        columns = [
            "Close",  # Close button column
            "Process ID",
            "Flags",  # Codesign flags column
            "Process",  # Process name column
            "Local Address",
            "Local Port", 
            "Remote Address",
            "Remote Port",
            "User ID",
            "FD",
            "State"
        ]
        
        self.setColumnCount(len(columns))
        self.setHorizontalHeaderLabels(columns)
        
        # Set column widths
        header = self.horizontalHeader()
        # Enable stretching of last section to fill available space
        header.setStretchLastSection(True)
        
        # Set all columns to Interactive mode to allow user resizing
        for i in range(len(columns)):
            if i == 0:  # Close button column - fixed width
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Fixed)
                self.setColumnWidth(i, 40)
            elif i == 10:  # State column - will stretch to fill remaining space
                # This column will stretch, but can still be resized manually
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
            else:
                # Use Interactive mode for all other columns to allow manual resizing
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)
        
        # Set reasonable default widths for columns
        self.setColumnWidth(1, 80)   # Process ID
        self.setColumnWidth(2, 100)  # Flags
        self.setColumnWidth(3, 120)  # Process
        self.setColumnWidth(4, 130)  # Local Address
        self.setColumnWidth(5, 80)   # Local Port
        self.setColumnWidth(6, 130)  # Remote Address
        self.setColumnWidth(7, 80)   # Remote Port
        self.setColumnWidth(8, 70)   # User ID
        self.setColumnWidth(9, 50)   # FD
        # State column width is automatic due to stretch mode
        
        # Enable sorting (will be set to True after initial data load)
        self.setSortingEnabled(False)
        
        # Enable row selection
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        
        # Set alternating row colors
        self.setAlternatingRowColors(True)
        
        # Set context menu
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        
        # Enable right-click on macOS
        self.setMouseTracking(True)
        
        # Hide row numbers (vertical header)
        self.verticalHeader().setVisible(False)
        
    def update_connections(self, connections: List[ConnectionInfo]):
        """Update the table with new connection data."""
        # Store current selection based on connection data, not row index
        current_connection = self.get_selected_connection()
        
        # Disable sorting temporarily during update
        sorting_enabled = self.isSortingEnabled()
        self.setSortingEnabled(False)
        
        # Store connections
        self.connections = connections
        self.connection_map.clear()
        
        # Update table
        self.setRowCount(len(connections))
        
        for row, conn in enumerate(connections):
            # Create a unique key for the connection
            conn_key = f"{conn.pid}_{conn.fd}_{conn.local_port}_{conn.remote_port}"
            
            # Close button column (column 0)
            close_item = QTableWidgetItem()
            close_item.setData(Qt.ItemDataRole.UserRole, conn_key)  # Store connection key
            close_item.setFlags(close_item.flags() & ~Qt.ItemFlag.ItemIsEditable)  # Make non-editable
            self.setItem(row, 0, close_item)
            
            # Process ID (column 1)
            pid_item = QTableWidgetItem()
            pid_item.setData(Qt.ItemDataRole.DisplayRole, conn.pid)  # Use numeric sorting
            pid_item.setData(Qt.ItemDataRole.UserRole, conn_key)  # Store connection key
            self.setItem(row, 1, pid_item)
            
            # Codesign Flags (column 2)
            flags = self.get_process_flags(conn.pid)
            flags_item = QTableWidgetItem(flags)
            flags_item.setData(Qt.ItemDataRole.UserRole, conn_key)
            # Color code based on flags
            if "runtime" in flags.lower():
                flags_item.setForeground(QColor(0, 128, 0))  # Green for hardened runtime
            elif flags:
                flags_item.setForeground(QColor(64, 64, 255))  # Blue for signed
            else:
                flags_item.setForeground(QColor(128, 128, 128))  # Gray for unsigned
            self.setItem(row, 2, flags_item)
            
            # Process Name (column 3)
            process_name = self.get_process_name(conn.pid)
            process_item = QTableWidgetItem(process_name)
            process_item.setData(Qt.ItemDataRole.UserRole, conn_key)
            self.setItem(row, 3, process_item)
            
            # Local Address (column 4)
            local_addr_item = QTableWidgetItem(conn.local_ip)
            local_addr_item.setData(Qt.ItemDataRole.UserRole, conn_key)
            self.setItem(row, 4, local_addr_item)
            
            # Local Port (column 5)
            local_port_item = QTableWidgetItem()
            local_port_item.setData(Qt.ItemDataRole.DisplayRole, conn.local_port)  # Numeric sorting
            local_port_item.setData(Qt.ItemDataRole.UserRole, conn_key)
            self.setItem(row, 5, local_port_item)
            
            # Remote Address (column 6)
            remote_addr_item = QTableWidgetItem(conn.remote_ip)
            remote_addr_item.setData(Qt.ItemDataRole.UserRole, conn_key)
            self.setItem(row, 6, remote_addr_item)
            
            # Remote Port (column 7)
            remote_port_item = QTableWidgetItem()
            remote_port_item.setData(Qt.ItemDataRole.DisplayRole, conn.remote_port)  # Numeric sorting
            remote_port_item.setData(Qt.ItemDataRole.UserRole, conn_key)
            self.setItem(row, 7, remote_port_item)
            
            # User ID (column 8)
            uid_item = QTableWidgetItem()
            uid_item.setData(Qt.ItemDataRole.DisplayRole, conn.uid)  # Numeric sorting
            uid_item.setData(Qt.ItemDataRole.UserRole, conn_key)
            self.setItem(row, 8, uid_item)
            
            # File Descriptor (column 9)
            fd_item = QTableWidgetItem()
            fd_item.setData(Qt.ItemDataRole.DisplayRole, conn.fd)  # Numeric sorting
            fd_item.setData(Qt.ItemDataRole.UserRole, conn_key)
            self.setItem(row, 9, fd_item)
            
            # State (column 10)
            state_item = QTableWidgetItem("ESTABLISHED")
            state_item.setForeground(QColor(0, 128, 0))  # Green color
            state_item.setData(Qt.ItemDataRole.UserRole, conn_key)
            self.setItem(row, 10, state_item)
            
            # Center align numeric columns (adjusted for Flags column)
            for col in [1, 5, 7, 8, 9]:
                item = self.item(row, col)
                if item:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            
            # Store connection in map with key
            self.connection_map[conn_key] = conn
        
        # Re-enable sorting (enable it after first load if it wasn't enabled before)
        if not sorting_enabled and self.rowCount() > 0:
            self.setSortingEnabled(True)
        else:
            self.setSortingEnabled(sorting_enabled)
        
        # Try to restore selection based on connection data
        if current_connection:
            current_key = f"{current_connection.pid}_{current_connection.fd}_{current_connection.local_port}_{current_connection.remote_port}"
            for row in range(self.rowCount()):
                item = self.item(row, 0)
                if item and item.data(Qt.ItemDataRole.UserRole) == current_key:
                    self.selectRow(row)
                    break
    
    def get_selected_connection(self) -> Optional[ConnectionInfo]:
        """Get the currently selected connection."""
        row = self.currentRow()
        if row >= 0:
            # Get the connection key from the first column of the selected row
            item = self.item(row, 0)
            if item:
                conn_key = item.data(Qt.ItemDataRole.UserRole)
                if conn_key in self.connection_map:
                    return self.connection_map[conn_key]
        return None
    
    def handle_close_button_click(self, row):
        """Handle click on close button in first column."""
        # Get the connection key from the clicked row
        item = self.item(row, 0)
        if item:
            conn_key = item.data(Qt.ItemDataRole.UserRole)
            if conn_key in self.connection_map:
                connection = self.connection_map[conn_key]
                self.close_connection_requested.emit(connection)


class TCPViewerWindow(QMainWindow):
    """Main window for TCP Viewer application."""
    
    def __init__(self):
        super().__init__()
        self.monitor_thread = None
        self.monitor_worker = None
        self.auto_refresh = True
        self.confirm_close = False  # New setting for close confirmation
        self.init_ui()
        self.start_monitoring()
        
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("TCP Connection Viewer")
        self.setGeometry(100, 100, 1000, 600)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create toolbar
        toolbar_layout = QHBoxLayout()
        
        # Filter textbox
        filter_label = QLabel("Filter:")
        toolbar_layout.addWidget(filter_label)
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter by Remote Address or Port...")
        self.filter_input.textChanged.connect(self.apply_filter)
        self.filter_input.setMaximumWidth(300)
        toolbar_layout.addWidget(self.filter_input)
        #self.filter_input.setText("216.221.209.61") # 216.221.209.61
        
        # Refresh button
        self.refresh_btn = QPushButton("Refresh Now")
        self.refresh_btn.clicked.connect(self.manual_refresh)
        toolbar_layout.addWidget(self.refresh_btn)
        
        # Actions button for selected connection
        self.actions_btn = QPushButton("Actions")
        self.actions_btn.setEnabled(False)
        self.actions_btn.clicked.connect(self.show_actions_menu)
        toolbar_layout.addWidget(self.actions_btn)
        
        # Auto-refresh checkbox
        self.auto_refresh_cb = QCheckBox("Auto Refresh")
        self.auto_refresh_cb.setChecked(True)
        self.auto_refresh_cb.stateChanged.connect(self.toggle_auto_refresh)
        toolbar_layout.addWidget(self.auto_refresh_cb)
        
        # Confirm close checkbox
        self.confirm_close_cb = QCheckBox("Confirm Close")
        self.confirm_close_cb.setChecked(False)
        self.confirm_close_cb.stateChanged.connect(self.toggle_confirm_close)
        toolbar_layout.addWidget(self.confirm_close_cb)
        
        # Always on top checkbox
        self.always_on_top_cb = QCheckBox("Always on Top")
        self.always_on_top_cb.setChecked(False)
        self.always_on_top_cb.stateChanged.connect(self.toggle_always_on_top)
        toolbar_layout.addWidget(self.always_on_top_cb)
        
        toolbar_layout.addStretch()
        
        # Connection count label
        self.count_label = QLabel("Connections: 0")
        toolbar_layout.addWidget(self.count_label)
        
        layout.addLayout(toolbar_layout)
        
        # Create table
        self.table = ConnectionTableWidget()
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.close_connection_requested.connect(self.close_connection)
        
        # Alternative context menu for macOS - using mouse press event
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.viewport().installEventFilter(self)
        
        # Enable/disable actions button based on selection
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        
        layout.addWidget(self.table)
        
        # Set up status bar
        self.statusBar().showMessage("Ready")
        
        # Apply dark theme styling (optional)
        self.apply_styling()

    def detect_dark_mode(self):
        # 1. Qt API
        try:
            from PyQt6.QtGui import QGuiApplication
            hints = QGuiApplication.styleHints()
            if hasattr(hints, "colorScheme"):
                from PyQt6.QtCore import Qt
                return hints.colorScheme() == Qt.ColorScheme.Dark
        except Exception:
            pass

        # 2. AppleScript fallback
        if sys.platform == "darwin":
            try:
                res = subprocess.run(
                    ["osascript", "-e",
                    'tell application "System Events" to get dark mode of appearance preferences'],
                    capture_output=True, text=True, timeout=1
                )
                if res.returncode == 0:
                    return res.stdout.strip().lower() == "true"
            except Exception:
                pass

            # 3. Original defaults fallback (works only under regular user)
            try:
                res = subprocess.run(
                    ["defaults", "read", "-g", "AppleInterfaceStyle"],
                    capture_output=True, text=True, timeout=0.5
                )
                return res.returncode == 0 and "Dark" in res.stdout
            except Exception:
                pass

        return False
        
    def apply_styling(self):
        """Apply custom styling to the application."""
        # Detect if we're using dark mode on macOS
        is_dark_mode = self.detect_dark_mode()

        if is_dark_mode:
            # Dark theme styles
            style = """
                QTableWidget {
                    gridline-color: #3a3a3a;
                    font-size: 12px;
                    background-color: #1e1e1e;
                    color: #e0e0e0;
                }
                QTableWidget::item {
                    padding: 4px;
                    background-color: #1e1e1e;
                    color: #e0e0e0;
                }
                QTableWidget::item:selected {
                    background-color: #308cc6;
                    color: white;
                }
                /* Ensure alternate rows also show selection */
                QTableWidget::item:alternate:selected {
                    background-color: #308cc6;
                    color: white;
                }
                QTableWidget::item:alternate {
                    background-color: #262626;
                }
                QHeaderView::section {
                    background-color: #2d2d2d;
                    color: #e0e0e0;
                    padding: 4px;
                    border: 1px solid #3a3a3a;
                    font-weight: bold;
                }
                QMenu {
                    background-color: #2d2d2d;
                    color: #e0e0e0;
                    border: 1px solid #3a3a3a;
                }
                QMenu::item {
                    padding: 5px 20px;
                    background-color: transparent;
                }
                QMenu::item:selected {
                    background-color: #308cc6;
                    color: white;
                }
                QMenu::separator {
                    height: 1px;
                    background-color: #3a3a3a;
                    margin: 5px 10px;
                }
                QPushButton {
                    padding: 5px 15px;
                    background-color: #2d2d2d;
                    color: #e0e0e0;
                    border: 1px solid #3a3a3a;
                }
                QPushButton:hover {
                    background-color: #3a3a3a;
                }
                QPushButton:pressed {
                    background-color: #1e1e1e;
                }
                QPushButton:disabled {
                    color: #606060;
                }
                QCheckBox {
                    padding: 5px;
                    color: #e0e0e0;
                }
                QLabel {
                    color: #e0e0e0;
                }
                QLineEdit {
                    padding: 5px;
                    background-color: #2d2d2d;
                    color: #e0e0e0;
                    border: 1px solid #3a3a3a;
                    border-radius: 3px;
                }
                QLineEdit:focus {
                    border: 1px solid #308cc6;
                }
                QStatusBar {
                    background-color: #2d2d2d;
                    color: #e0e0e0;
                }
            """
        else:
            # Light theme styles (original)
            style = """
                QTableWidget {
                    gridline-color: #d0d0d0;
                    font-size: 12px;
                }
                QTableWidget::item {
                    padding: 4px;
                }
                QTableWidget::item:selected {
                    background-color: #308cc6;
                    color: white; /* Better contrast */
                }
                /* Selection for alternate-colored rows */
                QTableWidget::item:alternate:selected {
                    background-color: #308cc6;
                    color: white;
                }
                QHeaderView::section {
                    background-color: #f0f0f0;
                    padding: 4px;
                    border: 1px solid #d0d0d0;
                    font-weight: bold;
                }
                QMenu {
                    background-color: white;
                }
                QPushButton {
                    padding: 5px 15px;
                }
                QCheckBox {
                    padding: 5px;
                }
                QLineEdit {
                    padding: 5px;
                    border: 1px solid #d0d0d0;
                    border-radius: 3px;
                }
                QLineEdit:focus {
                    border: 1px solid #308cc6;
                }
            """
        self.setStyleSheet(style)
        
    def start_monitoring(self):
        """Start the connection monitoring thread."""
        self.monitor_worker = ConnectionMonitor()
        self.monitor_thread = QThread()
        
        self.monitor_worker.moveToThread(self.monitor_thread)
        
        # Connect signals
        self.monitor_worker.connections_updated.connect(self.update_connections)
        self.monitor_worker.error_occurred.connect(self.handle_error)
        self.monitor_thread.started.connect(self.monitor_worker.start_monitoring)
        
        # Start thread
        self.monitor_thread.start()
        
    def stop_monitoring(self):
        """Stop the connection monitoring thread."""
        if self.monitor_worker:
            self.monitor_worker.stop_monitoring()
        if self.monitor_thread:
            self.monitor_thread.quit()
            self.monitor_thread.wait()
            
    def toggle_auto_refresh(self, state):
        """Toggle auto-refresh on/off."""
        self.auto_refresh = (state == Qt.CheckState.Checked.value)
    
    def toggle_confirm_close(self, state):
        """Toggle confirmation dialog for closing connections."""
        self.confirm_close = (state == Qt.CheckState.Checked.value)
    
    def toggle_always_on_top(self, state):
        """Toggle always on top window flag."""
        is_checked = (state == Qt.CheckState.Checked.value)
        if is_checked:
            self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
        else:
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowStaysOnTopHint)
        self.show()  # Window needs to be re-shown after changing flags
            
    def manual_refresh(self):
        """Manually refresh the connection list."""
        try:
            connections = _find_socket_fds()
            self.update_connections(connections)
            self.statusBar().showMessage("Refreshed", 2000)
        except Exception as e:
            self.handle_error(str(e))
    
    def apply_filter(self):
        """Filter table rows based on filter text."""
        filter_text = self.filter_input.text().lower()
        
        for row in range(self.table.rowCount()):
            # Get Remote Address (column 6) and Remote Port (column 7) - adjusted for Flags column
            process_item = self.table.item(row, 3)
            remote_addr_item = self.table.item(row, 6)
            remote_port_item = self.table.item(row, 7)
            
            if remote_addr_item and remote_port_item:
                remote_addr = remote_addr_item.text().lower()
                remote_port = str(remote_port_item.data(Qt.ItemDataRole.DisplayRole))
                process = process_item.text().lower()
                
                # Show row if filter text is found in remote address or port
                if filter_text in remote_addr or filter_text in remote_port or filter_text in process:
                    self.table.setRowHidden(row, False)
                else:
                    self.table.setRowHidden(row, True)
            else:
                # If items don't exist, hide the row
                self.table.setRowHidden(row, True)
        
        # Update connection count to show visible connections
        visible_count = sum(1 for row in range(self.table.rowCount()) if not self.table.isRowHidden(row))
        total_count = self.table.rowCount()
        if filter_text:
            self.count_label.setText(f"Connections: {visible_count}/{total_count}")
        else:
            self.count_label.setText(f"Connections: {total_count}")
            
    def update_connections(self, connections: List[ConnectionInfo]):
        """Update the connection table."""
        if not self.auto_refresh and self.sender() == self.monitor_worker:
            return  # Skip auto-updates if auto-refresh is disabled
            
        # Remember if we had a selection before update
        had_selection = self.table.get_selected_connection() is not None
        
        self.table.update_connections(connections)
        
        # Reapply filter after updating connections
        self.apply_filter()
        
        # Update count label (will be updated again by apply_filter if there's a filter)
        if not self.filter_input.text():
            self.count_label.setText(f"Connections: {len(connections)}")
        
        # Update status
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.statusBar().showMessage(f"Last updated: {timestamp}")
        
        # Update actions button state after table update
        self.on_selection_changed()
        
    def show_context_menu(self, position):
        """Show context menu for the selected connection."""
        # Ensure we have a valid selection at the click position
        item = self.table.itemAt(position)
        if item is not None:
            # Select the row at the click position
            self.table.selectRow(item.row())
        
        connection = self.table.get_selected_connection()
        if not connection:
            return
            
        # Verify the connection is still valid (important after sorting)
        if connection not in self.table.connections:
            QMessageBox.warning(self, "Error", "Selected connection is no longer valid. Please refresh.")
            return
            
        menu = QMenu(self)
        
        # Set native menu bar to False for better compatibility on macOS
        # Style is handled by the main stylesheet now
        
        # Add connection info header
        info_action = QAction(
            f"Connection: {connection.local_ip}:{connection.local_port} → "
            f"{connection.remote_ip}:{connection.remote_port}", 
            self
        )
        info_action.setEnabled(False)
        menu.addAction(info_action)
        menu.addSeparator()
        
        # Add close connection action
        close_action = menu.addAction("Close Connection")
        close_action.triggered.connect(
            lambda: QTimer.singleShot(0, lambda: self.close_connection(connection))
        )
        
        # Add copy actions
        menu.addSeparator()
        copy_local = menu.addAction("Copy Local Address")
        copy_local.triggered.connect(
            lambda: QTimer.singleShot(0, lambda: QApplication.clipboard().setText(f"{connection.local_ip}:{connection.local_port}"))
        )
        
        copy_remote = menu.addAction("Copy Remote Address")
        copy_remote.triggered.connect(
            lambda: QTimer.singleShot(0, lambda: QApplication.clipboard().setText(f"{connection.remote_ip}:{connection.remote_port}"))
        )
        
        copy_pid = menu.addAction(f"Copy Process ID ({connection.pid})")
        copy_pid.triggered.connect(
            lambda: QTimer.singleShot(0, lambda: QApplication.clipboard().setText(str(connection.pid)))
        )
        
        # Show menu at cursor position
        # Use QPoint to ensure proper position on macOS
        global_pos = self.table.viewport().mapToGlobal(position)
        # exec() will automatically close the menu when an action is triggered
        menu.exec(global_pos)
    
    def cleanup_context_menu(self):
        """Clean up context menu reference."""
        if hasattr(self, 'current_context_menu') and self.current_context_menu:
            self.current_context_menu.deleteLater()
            self.current_context_menu = None
    
    def close_menu_now(self):
        """Force close the current context menu (for Actions button menu)."""
        if hasattr(self, 'current_context_menu') and self.current_context_menu:
            self.current_context_menu.close()
            self.current_context_menu.deleteLater()
            self.current_context_menu = None
            QApplication.processEvents()
    
    def copy_and_close_menu(self, text: str):
        """Copy text to clipboard and close the Actions menu."""
        QApplication.clipboard().setText(text)
        self.close_menu_now()
    
    def close_connection_with_menu_close(self, connection: ConnectionInfo):
        """Close connection and ensure Actions menu is closed first."""
        self.close_menu_now()
        # Use QTimer to call close_connection after menu is fully closed
        QTimer.singleShot(10, lambda: self.close_connection(connection))
        
    def close_connection(self, connection: ConnectionInfo):
        """Close the selected TCP connection."""
        # Double-check we have the right connection
        if not connection:
            QMessageBox.warning(self, "Error", "No connection selected.")
            return
        
        if self.confirm_close:
            try:
                import subprocess
                result = subprocess.run(["ps", "-p", str(connection.pid), "-o", "comm="], 
                                      capture_output=True, text=True)
                process_name = result.stdout.strip() if result.returncode == 0 else "Unknown Process"
            except:
                process_name = "Unknown Process"
            
            reply = QMessageBox.question(
                self,
                "Close Connection",
                f"Are you sure you want to close the connection:\n\n"
                f"Process: {process_name} (PID: {connection.pid})\n"
                f"Local: {connection.local_ip}:{connection.local_port}\n"
                f"Remote: {connection.remote_ip}:{connection.remote_port}\n"
                f"File Descriptor: {connection.fd}\n\n"
                f"This action cannot be undone.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply != QMessageBox.StandardButton.Yes:
                return
        
        try:
            if os.geteuid() != 0 and connection.uid != os.geteuid():
                QMessageBox.warning(
                    self,
                    "Permission Denied",
                    "You need root privileges to close connections owned by other users.\n"
                    "Please run this application with sudo."
                )
                return

            _shutdown_sockfd(connection.pid, connection.fd, verbose=True)   
            self.manual_refresh()
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to close connection:\n{str(e)}"
            )
                
    def handle_error(self, error_msg: str):
        """Handle errors from the monitor thread."""
        self.statusBar().showMessage(f"Error: {error_msg}", 5000)
        
    def eventFilter(self, source, event):
        """Event filter to handle right-click and double-click on macOS."""
        if source == self.table.viewport():
            if event.type() == QEvent.Type.MouseButtonPress:
                if event.button() == Qt.MouseButton.RightButton:
                    item = self.table.itemAt(event.pos())
                    if item is not None:
                        self.table.selectRow(item.row())
                        self.show_context_menu(event.pos())
                        return True
                elif event.button() == Qt.MouseButton.LeftButton and event.modifiers() == Qt.KeyboardModifier.ControlModifier:
                    item = self.table.itemAt(event.pos())
                    if item is not None:
                        self.table.selectRow(item.row())
                        self.show_context_menu(event.pos())
                        return True
            elif event.type() == QEvent.Type.MouseButtonDblClick:
                item = self.table.itemAt(event.pos())
                if item is not None:
                    self.show_connection_details()
                    return True
        return super().eventFilter(source, event)
    
    def on_selection_changed(self):
        """Handle table selection change."""
        connection = self.table.get_selected_connection()
        has_selection = connection is not None
        self.actions_btn.setEnabled(has_selection)
        
        if has_selection:
            self.statusBar().showMessage(
                f"Selected: PID {connection.pid} | "
                f"{connection.local_ip}:{connection.local_port} → "
                f"{connection.remote_ip}:{connection.remote_port}",
                5000
            )
    
    def show_connection_details(self):
        """Show detailed information about the selected connection."""
        connection = self.table.get_selected_connection()
        if not connection:
            QMessageBox.warning(self, "No Selection", "Please select a connection first.")
            return
        
        try:
            import subprocess
            result = subprocess.run(["ps", "-p", str(connection.pid), "-o", "comm="], 
                                  capture_output=True, text=True)
            process_name = result.stdout.strip() if result.returncode == 0 else "Unknown"
        except:
            process_name = "Unknown"
        
        details = (
            f"Connection Details\n\n"
            f"Process: {process_name} (PID: {connection.pid})\n"
            f"File Descriptor: {connection.fd}\n"
            f"User ID: {connection.uid}\n\n"
            f"Local Endpoint: {connection.local_ip}:{connection.local_port}\n"
            f"Remote Endpoint: {connection.remote_ip}:{connection.remote_port}\n\n"
            f"Use ❌ or Actions button to manage this connection."
        )
        
        QMessageBox.information(self, "Connection Details", details)
    
    def show_actions_menu(self):
        """Show actions menu for the Actions button."""
        connection = self.table.get_selected_connection()
        if not connection:
            return
        
        menu = QMenu(self)
        
        # Add connection info header
        info_action = QAction(
            f"Connection: {connection.local_ip}:{connection.local_port} → "
            f"{connection.remote_ip}:{connection.remote_port}", 
            self
        )
        info_action.setEnabled(False)
        menu.addAction(info_action)
        menu.addSeparator()
        
        # Add close connection action
        close_action = QAction("Close Connection", self)
        close_action.triggered.connect(
            lambda checked=False, conn=connection: self.close_connection_with_menu_close(conn)
        )
        menu.addAction(close_action)
        
        # Add copy actions
        menu.addSeparator()
        copy_local = QAction("Copy Local Address", self)
        copy_local.triggered.connect(
            lambda checked=False, conn=connection: self.copy_and_close_menu(f"{conn.local_ip}:{conn.local_port}")
        )
        menu.addAction(copy_local)
        
        copy_remote = QAction("Copy Remote Address", self)
        copy_remote.triggered.connect(
            lambda checked=False, conn=connection: self.copy_and_close_menu(f"{conn.remote_ip}:{conn.remote_port}")
        )
        menu.addAction(copy_remote)
        
        copy_pid = QAction(f"Copy Process ID ({connection.pid})", self)
        copy_pid.triggered.connect(
            lambda checked=False, conn=connection: self.copy_and_close_menu(str(conn.pid))
        )
        menu.addAction(copy_pid)
        
        # Show menu below the button
        # Store menu reference to ensure it can be properly closed
        self.current_context_menu = menu
        menu.aboutToHide.connect(lambda: self.cleanup_context_menu())
        menu.exec(self.actions_btn.mapToGlobal(self.actions_btn.rect().bottomLeft()))
    
    def closeEvent(self, event):
        """Handle window close event."""
        self.stop_monitoring()
        event.accept()


def main():
    """Main entry point for the application."""
    app = QApplication(sys.argv)
    app.setApplicationName("TCP Viewer")
    
    # Check if running as root (recommended for full functionality)
    if os.geteuid() != 0:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setWindowTitle("TCP Viewer")
        msg.setText("Running without root privileges")
        msg.setInformativeText(
            "TCP Viewer is running without root privileges.\n\n"
            "You will only be able to:\n"
            "• View all connections\n"
            "• Close connections owned by your user\n\n"
            "To close any connection, please run with sudo:\n"
            "sudo python3 tcp_viewer.py"
        )
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()
    
    window = TCPViewerWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()