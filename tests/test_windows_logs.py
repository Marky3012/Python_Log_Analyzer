"""
Tests for Windows Event Log functionality.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

# Add the project root to the Python path
sys.path.append(str(Path(__file__).parent.parent.absolute()))

class TestWindowsLogs(unittest.TestCase):    
    def setUp(self):
        """Set up test environment."""
        # Mock Windows-specific imports
        self.win32_mock = MagicMock()
        self.win32evtlog_mock = MagicMock()
        self.win32con_mock = MagicMock()
        self.win32security_mock = MagicMock()
        
        # Create a mock for the Windows platform
        self.platform_system = patch('platform.system')
        self.mock_system = self.platform_system.start()
        self.mock_system.return_value = 'Windows'
        
        # Mock Windows modules
        sys.modules['win32evtlog'] = self.win32evtlog_mock
        sys.modules['win32con'] = self.win32con_mock
        sys.modules['win32security'] = self.win32security_mock
        
        # Import the module after setting up mocks
        from ingest.windows_logs import WindowsEventLogs
        self.WindowsEventLogs = WindowsEventLogs
    
    def tearDown(self):
        """Clean up after tests."""
        self.platform_system.stop()
        
    def test_init_windows(self):
        """Test initialization on Windows."""
        logs = self.WindowsEventLogs()
        self.assertTrue(logs.is_windows)
    
    @patch('os.path.exists')
    def test_find_windows_logs(self, mock_exists):
        """Test finding Windows log files."""
        # Setup mock
        mock_exists.return_value = True
        
        # Create test directory structure
        test_dir = r"C:\Windows\System32\winevt\Logs"
        test_files = [
            "Security.evtx",
            "System.evtx",
            "Application.evtx",
            "Microsoft-Windows-Sysmon%4Operational.evtx"
        ]
        
        # Mock os.listdir
        with patch('os.listdir') as mock_listdir:
            mock_listdir.return_value = test_files
            logs = self.WindowsEventLogs()
            found_logs = logs.find_windows_logs()
            
            # Verify the correct number of logs were found
            self.assertEqual(len(found_logs), 4)
            self.assertIn(os.path.join(test_dir, "Security.evtx"), found_logs)
    
    @patch('builtins.open')
    @patch('xml.etree.ElementTree.parse')
    def test_parse_evtx_file(self, mock_parse, mock_open):
        """Test parsing an EVTX file."""
        # Setup mock XML content
        mock_root = MagicMock()
        mock_system = MagicMock()
        mock_time_created = MagicMock()
        mock_time_created.get.return_value = "2023-01-01T12:00:00.1234567Z"
        mock_system.find.side_effect = [
            mock_time_created,  # TimeCreated
            MagicMock(text="4624"),  # EventID
            MagicMock(text="Security"),  # Channel
            MagicMock(text="COMPUTER01"),  # Computer
            MagicMock(text=4)  # Level
        ]
        mock_root.find.return_value = mock_system
        mock_parse.return_value.getroot.return_value = mock_root
        
        # Mock EVTX parsing
        with patch('ingest.windows_logs.Evtx.Evtx') as mock_evtx:
            mock_record = MagicMock()
            mock_record.xml.return_value = "<Event><System>...</System></Event>"
            mock_evtx.return_value.records.return_value = [mock_record]
            
            logs = self.WindowsEventLogs()
            events = list(logs.parse_evtx_file("test.evtx"))
            
            # Verify an event was parsed
            self.assertTrue(len(events) > 0)
            self.assertEqual(events[0]['event_id'], 4624)
    
    def test_normalize_windows_event(self):
        """Test normalizing a Windows event."""
        logs = self.WindowsEventLogs()
        
        # Test a security event
        event = {
            'timestamp': '2023-01-01T12:00:00Z',
            'event_id': 4624,
            'channel': 'Security',
            'computer': 'COMPUTER01',
            'level': 0,
            'user': 'S-1-5-21-1234567890-1234567890-1234567890-1001'
        }
        
        normalized = logs._normalize_windows_event(
            event, 
            {'TargetUserName': 'admin', 'IpAddress': '192.168.1.100'},
            'test.evtx'
        )
        
        self.assertEqual(normalized['event_type'], 'auth_success')
        self.assertEqual(normalized['source'], 'windows_security')
        self.assertEqual(normalized['ip'], '192.168.1.100')

if __name__ == '__main__':
    unittest.main()
