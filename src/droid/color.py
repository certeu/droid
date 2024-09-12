import logging
from colorama import Fore
from pythonjsonlogger import jsonlogger

class AzureLogFilter(logging.Filter):
    """Azure logging filter
    Class to register a filter to suppress debug logs from Azure
    """
    def __init__(self, debug_mode=False):
        super().__init__()
        self.debug_mode = debug_mode

    def filter(self, record):
        if not self.debug_mode and record.name.startswith('azure'):
            return False
        return True

class ColorFormatter(logging.Formatter):
    """Color Formatter
    Class to register the colors output for DROID logging
    """
    COLORS = {
        "WARNING": Fore.MAGENTA,
        "ERROR": Fore.RED,
        "DEBUG": Fore.BLUE,
        "INFO": Fore.GREEN,
        "CRITICAL": Fore.RED
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, "")
        if color:
            record.name = color + record.name
            record.levelname = color + record.levelname
            record.msg = color + record.msg
        return logging.Formatter.format(self, record)

class ColorLogger(logging.Logger):
    def __init__(self, name, debug_mode=False, json_enabled=False, json_stdout=False, log_file=None):
        if debug_mode:
            super().__init__(name, logging.DEBUG)
        else:
            super().__init__(name, logging.WARNING)
        if log_file:
            json_enabled = True
        if not log_file:
            log_file = "droid.log"
        self.json_enabled = json_enabled
        self.json_stdout = json_stdout
        self.log_file = log_file
        self.debug_mode = debug_mode


        self.setup_handlers()

    def setup_handlers(self):
        """Setup the handlers for logging depending on the options passed."""
        format_str = "%(asctime)s:%(levelname)s:%(name)s:%(message)s"
        self.handlers = []  # Clear existing handlers

        if self.json_enabled:
            # Set up JSON file out
            json_formatter = jsonlogger.JsonFormatter(format_str)
            # Log JSON output to a file
            json_file_handler = logging.FileHandler(self.log_file)
            json_file_handler.setFormatter(json_formatter)
            self.addHandler(json_file_handler)

        if self.json_stdout:
            stdout_formater = jsonlogger.JsonFormatter(format_str)
        else:
            # Console logging with color formatting if JSON is not enabled for stdout
            stdout_formater = ColorFormatter(format_str)
        console = logging.StreamHandler()
        console.setFormatter(stdout_formater)

        # Add AzureLogFilter only when not in debug mode
        if not self.debug_mode:
            azure_filter = AzureLogFilter(debug_mode=self.debug_mode)
            console.addFilter(azure_filter)

        self.addHandler(console)
