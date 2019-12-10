from defectdojo_api import defectdojo
import os
import datetime
from calendar import monthrange


# Make a few tweaks to the api wrapper
class DefectDojoExtended(defectdojo):
    # Add in additional Product attributes (prod_type, origin, lifecycle, team_manager)
    def create_product(self, name, description, prod_type, origin="Quest Diagnostics", lifecycle="Production",
                       team_manager=0):
        """Creates a product with the given properties.

        :param name: Product name.
        :param description: Product key id..
        :param prod_type: Product type.
        :param origin: Client origin
        :param lifecycle: Lifecycle stage
        :param team_manager: UserID for Team Manager
        """

        data = {
            'name': name,
            'description': description,
            'prod_type': prod_type,
            'origin': origin,
            'lifecycle': lifecycle,
            'team_manager': team_manager
        }

        return self._request('POST', 'products/', data=data)


# Setup DefectDojo connection information
host = 'http://localhost:8000'
api_key = os.environ['DOJO_API_KEY']
user = 'admin'

"""
#Optionally, specify a proxy
proxies = {
  'http': 'http://localhost:8080',
  'https': 'http://localhost:8080',
}
#proxies=proxies
"""

# Instantiate the DefectDojo api wrapper
dd = defectdojo.DefectDojoAPI(host, api_key, user, debug=False)

user_id = 10  # The "Unassigned" User


def create_qtr_engagement(product_id, product_name, year, quarter):
    month = 0
    if quarter == 1: month = 1
    if quarter == 2: month = 4
    if quarter == 3: month = 7
    if quarter == 4: month = 10
    if month == 0: raise Exception('Invalid value provided for quarter. The value of quarter was: {}'.format(quarter))

    start_date = datetime.date(year, month, 1)
    end_date = datetime.date(year, month + 2,
                             monthrange(year, (month + 2))[1])  # Gets the correct last day of the month

    print("Creating engagement: " + "Q" + quarter + year + " " + product_name + " Scans")
    engagement = dd.create_engagement("Q" + quarter + year + " " + product_name + " Scans", product_id, user_id,
                                      "Waiting for Resource", start_date.strftime("%Y-%m-%d"),
                                      end_date.strftime("%Y-%m-%d"), active='False',
                                      pen_test='False', check_list='False', threat_model='False', risk_path="",
                                      test_strategy="https://172.30.2.10/index.php/Quest_Vulnerability_Scans",
                                      progress="",
                                      done_testing='False', engagement_type="Interactive", build_id=None,
                                      commit_hash=None, branch_tag=None, build_server=None,
                                      source_code_management_server=None, source_code_management_uri=None,
                                      orchestration_engine=None,
                                      description="See the Engagement Presets below for details on performing this engagement.\n\nMore information about Quest scans can be found in the Wiki at: https://172.30.2.10/index.php/Quest_Vulnerability_Scans")
    engagement_id = engagement.id()
    print("Success: Engagement ID " + engagement_id + " created.")
    return engagement


def create_product_engagement(product_name, product_desc, year, quarter):
    # Create a product
    prod_type = 1  # 1 - Web App, product type
    print("Creating product: " + product_name)
    product = dd.create_product(product_name, product_desc, prod_type)
    if product.success:
        # Get the product id
        product_id = product.id()
        print("Success: Product ID " + product_id + " created.")

        print("Creating engagement: " + "Q" + quarter + year + " " + product_name + " Scans")
        engagement = create_qtr_engagement(product_id, product_name, year, quarter)
        engagement_id = engagement.id()
        print("Success: Engagement ID " + engagement_id + " created.")


def create_product_quarterly_engagements(product_name, product_desc, start_year, end_year, scope_size):
    # Create a product
    prod_type = 1  # 1 - Web App, product type
    print("Creating product: " + product_name)
    product = dd.create_product(product_name, product_desc, prod_type)
    if product.success:
        # Get the product id
        product_id = product.id()
        print("Success: Product ID " + product_id + " created.")

        # For each year from start_year to end_year, inclusive
        yr = start_year
        while yr <= end_year:
            # Create the product and an engagement for each quarter
            for qtr in range(1, 4, 1):
                create_qtr_engagement(product_id, product_name, yr, qtr)
            yr = yr + 1


##### Create Products, Engagements and Tests ########
quest_apps = {}

quest_apps["applicant.examone.com"] = "https://applicant.examone.com"
quest_apps["eLabs for Hospitals"] = "https://stagelc.questdiagnostics.com"
quest_apps["CaseViewWeb"] = "https://caseviewweb.examone.com/CaseViewWeb"
