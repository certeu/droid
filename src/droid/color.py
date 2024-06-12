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
    def __init__(self, name, debug_mode=False):
        super().__init__(name, logging.DEBUG)
        self.json_enabled = False
        self.debug_mode = debug_mode

        self.setup_handlers()

    def setup_handlers(self):
        format_str = "%(asctime)s:%(levelname)s:%(name)s:%(message)s"
        self.handlers = []

        if self.json_enabled:
            json_formatter = jsonlogger.JsonFormatter(format_str)
            json_handler = logging.FileHandler('droid.log')
            json_handler.setFormatter(json_formatter)
            self.addHandler(json_handler)
            console = logging.StreamHandler()
            color_formatter = ColorFormatter(format_str)
            console.setFormatter(color_formatter)
            self.addHandler(console)
        else:
            color_formatter = ColorFormatter(format_str)
            console = logging.StreamHandler()
            console.setFormatter(color_formatter)

            # Add AzureLogFilter only when not in debug mode
            if not self.debug_mode:
                azure_filter = AzureLogFilter(debug_mode=self.debug_mode)
                console.addFilter(azure_filter)

            self.addHandler(console)

    def enable_json_logging(self):
        self.json_enabled = True
        self.setup_handlers()
