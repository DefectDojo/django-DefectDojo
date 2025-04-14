#!/usr/bin/python3
import collections
import logging
import re
import socket
import sys
import time
from urllib.parse import urlparse

from prettytable import PrettyTable
from zapv2 import ZAPv2

logger = logging.getLogger(__name__)


class Main:
    if __name__ == "__main__":

        address = "127.0.0.1"
        port = 8080

        logger.info("Checking if ZAP is running, connecting to ZAP on http://" + address + ":" + str(port))
        s = socket.socket()

        try:
            s.connect((address, port))
        except OSError:
            logger.info("Error connecting to ZAP, exiting.")
            sys.exit(0)

        zap = ZAPv2(proxies={"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"})
        apikey = ""

        # user_input_obj = User_Input() #Creating object for class User_Input
        targetURL = "http://dojo:8000"

        # targetURLregex = "\Q" + targetURL + "\E.*"  # Regular expression to be considered within our context.
        # The above line is flake8 violation as \Q and \E are not supported by python
        targetURLregex = re.escape(targetURL)

        # Defining context name as hostname from URL and creating context using it.
        contextname = urlparse(targetURL).netloc
        logger.info("Context Name: " + contextname)

        # Step1: Create context
        contextid = zap.context.new_context(contextname, apikey)
        logger.info("ContextID: " + contextid)

        # Step2: Include in the context
        result = zap.context.include_in_context(contextname, targetURLregex, apikey)
        logger.info("URL regex defined in context: " + result)

        # Step3: Session Management - Default is cookieBasedSessionManagement
        result = zap.sessionManagement.set_session_management_method(contextid, "cookieBasedSessionManagement", None, apikey)
        logger.info("Session method defined: " + result)

        loginUrl = "http://os.environ['DD_BASE_URL']/login"
        # loginUrlregex = "\Q" + loginUrl + "\E.*"
        # The above line is flake8 violation as \Q and \E are not supported by python
        loginURLregex = re.escape(loginUrl)
        result = zap.context.exclude_from_context(contextname, ".*logout.*", apikey)
        result = zap.context.exclude_from_context(contextname, ".*/static/.*", apikey)

        # Wait for passive scanning to complete
        while (int(zap.pscan.records_to_scan) > 0):
            logger.info("Records to passive scan : " + zap.pscan.records_to_scan)
            time.sleep(15)
        logger.info("Passive scanning complete")

        logger.info("Actively Scanning target " + targetURL)
        ascan_id = zap.ascan.scan(targetURL, None, None, None, None, None, apikey)  # Can provide more options for active scan here instead of using None.
        while (int(zap.ascan.status(ascan_id)) < 100):
            logger.info("Scan progress %: " + zap.ascan.status(ascan_id))
            time.sleep(15)

        logger.info("Scan completed")

        # Report the results
        sort_by_url = collections.defaultdict(list)
        for alert in zap.core.alerts():
            sort_by_url[alert["url"]].append({
                                        "risk": alert["risk"],
                                        "alert": alert["alert"],
                                            })

        summary = PrettyTable(["Risk", "Count"])
        summary.padding_width = 1
        summary.align = "l"
        info = 0
        low = 0
        medium = 0
        high = 0

        for url in sort_by_url:

            for details in sort_by_url[url]:
                if details["risk"] == "Informational":
                    info += 1
                if details["risk"] == "Low":
                    low += 1
                if details["risk"] == "Medium":
                    medium += 1
                if details["risk"] == "High":
                    high += 1

        summary.add_row(["Informational", info])
        summary.add_row(["Low", low])
        summary.add_row(["Medium", medium])
        summary.add_row(["High", high])
        logger.info(summary)

        for url in sort_by_url:
            logger.info("\n" + url)

            results = PrettyTable(["Risk", "Description"])
            results.padding_width = 1
            results.align = "l"
            results.sortby = "Risk"

            for details in sort_by_url[url]:
                results.add_row([details["risk"], details["alert"]])

            logger.info(results)
