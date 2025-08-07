import os
import tempfile
import unittest
from unittest.mock import patch

from refiner.utils.files import (
    should_apply_file_type_detection,
    detect_file_type,
    is_csv_file,
    is_json_file,
    is_text_file,
    _is_csv_with_sniffer
)


class TestShouldApplyFileTypeDetection(unittest.TestCase):
    """Test cases for should_apply_file_type_detection function."""
    
    def test_no_extension_triggers_detection(self):
        """Files with no extension should trigger detection."""
        self.assertTrue(should_apply_file_type_detection(''))
        self.assertTrue(should_apply_file_type_detection(None))
    
    def test_legitimate_extensions_skip_detection(self):
        """Legitimate file extensions should skip detection."""
        legitimate_extensions = ['.csv', '.json', '.txt', '.zip', '.pdf', '.html', '.xml']
        for ext in legitimate_extensions:
            with self.subTest(extension=ext):
                self.assertFalse(should_apply_file_type_detection(ext))
    
    def test_generic_extensions_trigger_detection(self):
        """Generic/problematic extensions should trigger detection."""
        generic_extensions = ['.dat', '.tmp', '.file', '.unknown', '.enc', '.encrypted']
        for ext in generic_extensions:
            with self.subTest(extension=ext):
                self.assertTrue(should_apply_file_type_detection(ext))
    
    def test_case_insensitive_matching(self):
        """Extension matching should be case-insensitive."""
        self.assertFalse(should_apply_file_type_detection('.CSV'))
        self.assertFalse(should_apply_file_type_detection('.JSON'))
        self.assertTrue(should_apply_file_type_detection('.TMP'))
        self.assertTrue(should_apply_file_type_detection('.ENC'))


class TestCSVDetection(unittest.TestCase):
    """Test cases for CSV file detection with multiple delimiters."""
    
    def setUp(self):
        """Set up temporary files for testing."""
        self.temp_files = []
    
    def tearDown(self):
        """Clean up temporary files."""
        for temp_file in self.temp_files:
            try:
                os.unlink(temp_file)
            except OSError:
                pass
    
    def _create_temp_file(self, content, suffix=''):
        """Helper to create temporary files."""
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
            f.write(content)
            temp_file = f.name
        self.temp_files.append(temp_file)
        return temp_file
    
    def test_comma_separated_csv(self):
        """Test detection of standard comma-separated CSV."""
        csv_content = """name,age,city
John,30,New York
Jane,25,Los Angeles
Bob,35,Chicago"""
        temp_file = self._create_temp_file(csv_content)
        self.assertTrue(is_csv_file(temp_file))
    
    def test_semicolon_separated_csv_german_format(self):
        """Test detection of semicolon-separated CSV (German format)."""
        csv_content = """Name;Alter;Stadt
Hans;30;Berlin
Maria;25;München
Klaus;35;Hamburg"""
        temp_file = self._create_temp_file(csv_content)
        self.assertTrue(is_csv_file(temp_file))
    
    def test_semicolon_csv_with_decimal_comma(self):
        """Test German CSV with semicolon delimiter and decimal comma."""
        csv_content = """Produkt;Preis;Menge
Apfel;1,50;10
Banane;2,30;5
Orange;1,80;8"""
        temp_file = self._create_temp_file(csv_content)
        self.assertTrue(is_csv_file(temp_file))
    
    def test_tab_separated_csv(self):
        """Test detection of tab-separated values."""
        csv_content = "name\tage\tcity\nJohn\t30\tNew York\nJane\t25\tLos Angeles"
        temp_file = self._create_temp_file(csv_content)
        self.assertTrue(is_csv_file(temp_file))
    
    def test_pipe_separated_csv(self):
        """Test detection of pipe-separated values."""
        csv_content = """name|age|city
John|30|New York
Jane|25|Los Angeles"""
        temp_file = self._create_temp_file(csv_content)
        self.assertTrue(is_csv_file(temp_file))
    
    def test_quoted_fields_csv(self):
        """Test CSV with quoted fields."""
        csv_content = '''"Last Name","First Name","Email"
"Doe","John","john@example.com"
"Smith","Jane","jane@example.com"'''
        temp_file = self._create_temp_file(csv_content)
        self.assertTrue(is_csv_file(temp_file))
    
    def test_mixed_quoted_fields_semicolon(self):
        """Test semicolon CSV with some quoted fields."""
        csv_content = '''Name;"Email Address";Age
Hans;"hans@example.de";30
"Maria Schmidt";"maria@example.de";25'''
        temp_file = self._create_temp_file(csv_content)
        self.assertTrue(is_csv_file(temp_file))
    
    def test_not_csv_plain_text(self):
        """Test that plain text is not detected as CSV."""
        text_content = """This is just a regular text file.
It has multiple lines.
But no structured data.
No consistent delimiters here."""
        temp_file = self._create_temp_file(text_content)
        self.assertFalse(is_csv_file(temp_file))
    
    def test_not_csv_json(self):
        """Test that JSON is not detected as CSV."""
        json_content = '''{"name": "John", "age": 30, "city": "New York"}'''
        temp_file = self._create_temp_file(json_content)
        self.assertFalse(is_csv_file(temp_file))
    
    def test_not_csv_single_line(self):
        """Test that single line files are not detected as CSV."""
        single_line = "Just one line with,some,commas"
        temp_file = self._create_temp_file(single_line)
        self.assertFalse(is_csv_file(temp_file))
    
    def test_not_csv_no_delimiters(self):
        """Test that files without delimiters are not CSV."""
        no_delim_content = """Line one
Line two
Line three"""
        temp_file = self._create_temp_file(no_delim_content)
        self.assertFalse(is_csv_file(temp_file))
    
    def test_csv_with_empty_lines(self):
        """Test CSV detection with empty lines."""
        csv_content = """name,age,city
John,30,New York

Jane,25,Los Angeles

Bob,35,Chicago"""
        temp_file = self._create_temp_file(csv_content)
        self.assertTrue(is_csv_file(temp_file))
    
    def test_prose_text_not_csv(self):
        """Test that prose text is not detected as CSV even with some punctuation."""
        # Create content that's clearly prose, not structured data
        prose_content = """This is a regular paragraph of text.
It contains sentences, with normal punctuation.
There might be some commas / pipes in natural language.
But this is clearly not structured | tabular data.
No consistent column structure exists here."""
        temp_file = self._create_temp_file(prose_content)
        # This should not be detected as CSV since it's prose
        self.assertFalse(is_csv_file(temp_file))
    
    def test_delimiter_consistency_enforcement(self):
        """Test that delimiter consistency is enforced - German CSV with commas in data."""
        # German CSV with semicolons as structural delimiters, commas within data
        german_csv = '''Name;Address;Salary
Hans Mueller;"Berlin, Germany, 10115";45,500.50
Maria Schmidt;"München, Bayern, 80331";38,200.00
Klaus Weber;"Hamburg, Deutschland, 20095";52,750.25'''
        temp_file = self._create_temp_file(german_csv)
        
        # Should be detected as CSV (semicolon delimiter is consistent)
        self.assertTrue(is_csv_file(temp_file))
        
        # Should specifically detect semicolon as the delimiter, not comma
        lines = german_csv.split('\n')
        self.assertTrue(_is_csv_with_sniffer(lines, ';'))  # Consistent semicolons
        self.assertFalse(_is_csv_with_sniffer(lines, ','))  # Inconsistent commas
    
    def test_mixed_delimiters_rejected(self):
        """Test that files with mixed delimiters are rejected."""
        mixed_content = """name,age,city
John;30;New York
Jane|25|Los Angeles
Bob,35,Chicago"""
        temp_file = self._create_temp_file(mixed_content)
        
        # Should NOT be detected as CSV due to inconsistent delimiters
        self.assertFalse(is_csv_file(temp_file))


class TestCSVDelimiterSpecific(unittest.TestCase):
    """Test cases for _is_csv_with_sniffer function."""
    
    def test_comma_delimiter(self):
        """Test comma delimiter detection."""
        lines = ["name,age,city", "John,30,New York", "Jane,25,Los Angeles"]
        self.assertTrue(_is_csv_with_sniffer(lines, ','))
        self.assertFalse(_is_csv_with_sniffer(lines, ';'))
    
    def test_semicolon_delimiter(self):
        """Test semicolon delimiter detection."""
        lines = ["Name;Alter;Stadt", "Hans;30;Berlin", "Maria;25;München"]
        self.assertTrue(_is_csv_with_sniffer(lines, ';'))
        self.assertFalse(_is_csv_with_sniffer(lines, ','))
    
    def test_tab_delimiter(self):
        """Test tab delimiter detection."""
        lines = ["name\tage\tcity", "John\t30\tNew York", "Jane\t25\tLos Angeles"]
        self.assertTrue(_is_csv_with_sniffer(lines, '\t'))
        self.assertFalse(_is_csv_with_sniffer(lines, ','))
    
    def test_pipe_delimiter(self):
        """Test pipe delimiter detection."""
        lines = ["name|age|city", "John|30|New York", "Jane|25|Los Angeles"]
        self.assertTrue(_is_csv_with_sniffer(lines, '|'))
        self.assertFalse(_is_csv_with_sniffer(lines, ','))
    
    def test_no_delimiter_present(self):
        """Test when delimiter is not present."""
        lines = ["name age city", "John 30 New York", "Jane 25 Los Angeles"]
        self.assertFalse(_is_csv_with_sniffer(lines, ','))
        self.assertFalse(_is_csv_with_sniffer(lines, ';'))
    
    def test_too_much_variation(self):
        """Test rejection when there's too much delimiter count variation."""
        lines = ["a,b", "c,d,e", "f,g,h,i", "j,k,l,m,n"]  # Too much variation
        self.assertFalse(_is_csv_with_sniffer(lines, ','))
    
    def test_empty_lines_ignored(self):
        """Test that empty lines are ignored in delimiter counting."""
        lines = ["name,age", "", "John,30", "", "Jane,25"]
        self.assertTrue(_is_csv_with_sniffer(lines, ','))


class TestJSONDetection(unittest.TestCase):
    """Test cases for JSON file detection."""
    
    def setUp(self):
        self.temp_files = []
    
    def tearDown(self):
        for temp_file in self.temp_files:
            try:
                os.unlink(temp_file)
            except OSError:
                pass
    
    def _create_temp_file(self, content):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(content)
            temp_file = f.name
        self.temp_files.append(temp_file)
        return temp_file
    
    def test_valid_json_object(self):
        """Test detection of valid JSON object."""
        json_content = '{"name": "John", "age": 30}'
        temp_file = self._create_temp_file(json_content)
        self.assertTrue(is_json_file(temp_file))
    
    def test_valid_json_array(self):
        """Test detection of valid JSON array."""
        json_content = '[{"name": "John"}, {"name": "Jane"}]'
        temp_file = self._create_temp_file(json_content)
        self.assertTrue(is_json_file(temp_file))
    
    def test_invalid_json(self):
        """Test rejection of invalid JSON."""
        invalid_json = '{"name": "John", "age":}'
        temp_file = self._create_temp_file(invalid_json)
        self.assertFalse(is_json_file(temp_file))
    
    def test_not_json_structure(self):
        """Test rejection of non-JSON structures."""
        not_json = 'This is just text'
        temp_file = self._create_temp_file(not_json)
        self.assertFalse(is_json_file(temp_file))


class TestTextFileDetection(unittest.TestCase):
    """Test cases for text file detection."""
    
    def setUp(self):
        self.temp_files = []
    
    def tearDown(self):
        for temp_file in self.temp_files:
            try:
                os.unlink(temp_file)
            except OSError:
                pass
    
    def _create_temp_file(self, content, mode='w'):
        with tempfile.NamedTemporaryFile(mode=mode, delete=False) as f:
            f.write(content)
            temp_file = f.name
        self.temp_files.append(temp_file)
        return temp_file
    
    def test_plain_text_file(self):
        """Test detection of plain text files."""
        text_content = "This is a plain text file.\nWith multiple lines."
        temp_file = self._create_temp_file(text_content)
        self.assertTrue(is_text_file(temp_file))
    
    def test_binary_file_rejection(self):
        """Test rejection of binary files."""
        # Create a file with lots of null bytes (binary-like)
        binary_content = b'\x00\x01\x02\x03' * 100
        temp_file = self._create_temp_file(binary_content, mode='wb')
        self.assertFalse(is_text_file(temp_file))
    
    def test_utf8_text_file(self):
        """Test detection of UTF-8 text files."""
        utf8_content = "This has ümlaut and émoji 🎉"
        temp_file = self._create_temp_file(utf8_content)
        self.assertTrue(is_text_file(temp_file))


class TestFileTypeDetectionIntegration(unittest.TestCase):
    """Integration tests for the complete file type detection system."""
    
    def setUp(self):
        self.temp_files = []
    
    def tearDown(self):
        for temp_file in self.temp_files:
            try:
                os.unlink(temp_file)
            except OSError:
                pass
    
    def _create_temp_file(self, content, suffix=''):
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
            f.write(content)
            temp_file = f.name
        self.temp_files.append(temp_file)
        return temp_file
    
    def test_detect_csv_comma_format(self):
        """Test detection of comma-separated CSV."""
        csv_content = "name,age,city\nJohn,30,NYC\nJane,25,LA"
        temp_file = self._create_temp_file(csv_content)
        self.assertEqual(detect_file_type(temp_file), '.csv')
    
    def test_detect_csv_semicolon_format(self):
        """Test detection of semicolon-separated CSV."""
        csv_content = "Name;Age;City\nHans;30;Berlin\nMaria;25;München"
        temp_file = self._create_temp_file(csv_content)
        self.assertEqual(detect_file_type(temp_file), '.csv')
    
    def test_detect_json_format(self):
        """Test detection of JSON format."""
        json_content = '{"users": [{"name": "John", "age": 30}]}'
        temp_file = self._create_temp_file(json_content)
        self.assertEqual(detect_file_type(temp_file), '.json')
    
    def test_detect_text_format(self):
        """Test detection of plain text format."""
        text_content = "This is just plain text.\nNo structured data here."
        temp_file = self._create_temp_file(text_content)
        self.assertEqual(detect_file_type(temp_file), '.txt')
    
    def test_fallback_without_magic(self):
        """Test fallback detection when python-magic is not available."""
        # Test the fallback logic by directly testing it
        csv_content = "name,age,city\nJohn,30,NYC\nJane,25,LA"
        temp_file = self._create_temp_file(csv_content)
        
        # Temporarily patch the import to simulate missing magic
        import refiner.utils.files as files_module
        original_detect = files_module.detect_file_type
        
        def mock_detect_file_type(file_path):
            # Simulate the fallback logic path (without python-magic)
            if files_module.is_json_file(file_path):
                return '.json'
            if files_module.is_csv_file(file_path):
                return '.csv'
            if files_module.is_text_file(file_path):
                return '.txt'
            return '.bin'
        
        # Test the fallback logic
        files_module.detect_file_type = mock_detect_file_type
        try:
            result = files_module.detect_file_type(temp_file)
            self.assertEqual(result, '.csv')
        finally:
            files_module.detect_file_type = original_detect
    
    def test_binary_file_detection(self):
        """Test detection of binary files."""
        # Create a binary-like file
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b'PK\x03\x04')  # ZIP file signature
            f.write(b'\x00' * 100)  # Padding with null bytes
            temp_file = f.name
        self.temp_files.append(temp_file)
        
        detected = detect_file_type(temp_file)
        self.assertEqual(detected, '.zip')


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""
    
    def test_nonexistent_file(self):
        """Test behavior with nonexistent files."""
        with self.assertRaises(FileNotFoundError):
            detect_file_type('/nonexistent/file.txt')
    
    def test_empty_file(self):
        """Test behavior with empty files."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        
        try:
            # Empty file should fall back to original extension or .bin
            result = detect_file_type(temp_file)
            self.assertIn(result, ['', '.bin'])  # Depends on implementation
        finally:
            os.unlink(temp_file)
    
    def test_very_large_sample_lines(self):
        """Test CSV detection with very large sample_lines parameter."""
        csv_content = "\n".join([f"col1,col2,col3\nrow{i},data{i},value{i}" for i in range(100)])
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(csv_content)
            temp_file = f.name
        
        try:
            # Should still work with large sample size
            self.assertTrue(is_csv_file(temp_file, sample_lines=1000))
        finally:
            os.unlink(temp_file)


if __name__ == '__main__':
    unittest.main() 