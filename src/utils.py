import json


def load_config(config_path="config/config.json"):
    """
    Load JSON configuration file.
    """

    with open(config_path, "r") as file:
        return json.load(file)