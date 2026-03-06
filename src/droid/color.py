import logging
from rich.logging import RichHandler
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
        """Setup the handlers for logging using Rich for console output."""
        json_format_str = "%(asctime)s:%(levelname)s:%(name)s:%(message)s"
        self.handlers = []  # Clear existing handlers

        if self.json_enabled:
            # Set up JSON file output
            json_formatter = jsonlogger.JsonFormatter(json_format_str)
            json_file_handler = logging.FileHandler(self.log_file)
            json_file_handler.setFormatter(json_formatter)
            self.addHandler(json_file_handler)

        if self.json_stdout:
            stdout_formatter = jsonlogger.JsonFormatter(json_format_str)
            console = logging.StreamHandler()
            console.setFormatter(stdout_formatter)
        else:
            console = RichHandler(
                rich_tracebacks=True,
                show_path=False,
                markup=True,
                log_time_format="%Y-%m-%d %H:%M:%S",
            )

        # Add AzureLogFilter only when not in debug mode
        if not self.debug_mode:
            azure_filter = AzureLogFilter(debug_mode=self.debug_mode)
            console.addFilter(azure_filter)

        self.addHandler(console)
