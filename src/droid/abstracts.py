from abc import ABC, abstractmethod


class AbstractPlatform(ABC):
    """
    AbstractRule is an abstract base class that defines the structure for a platform.
    It has three abstract methods: create_rule, remove_rule
    """

    def __init__(self, name: str):
        """
        Initialize the platform.
        """
        self.platform_name = name

    @abstractmethod
    def create_rule(self):
        """
        Create a detection rule. This method should be implemented by subclasses.
        """
        raise NotImplemented()

    @abstractmethod
    def get_rule(self):
        """
        Get the parameter from a rule. This method should be implemented by subclasses.
        """
        raise NotImplemented()

    @abstractmethod
    def remove_rule(self):
        """
        Remove a rule. This method should be implemented by subclasses.
        """
        raise NotImplemented()
