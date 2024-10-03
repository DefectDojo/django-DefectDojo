from dojo.tools.appcheck_web_application_scanner.engines.base import BaseEngineParser


class OpenVASScannerEngineParser(BaseEngineParser):

    """
    Parser for data from the OpenVAS scanning engine.

    Shares all functionality with BaseEngineParser, but registered under an explicit name.
    """

    SCANNING_ENGINE = "OpenVASScanner"
