import os
import requests
from datetime import datetime, timedelta

# Set up the GitHub and Slack tokens from environment variables
GH_TOKEN = os.getenv("GH_TOKEN")
SLACK_TOKEN = os.getenv("SLACK_TOKEN")
REPO_OWNER = "DefectDojo"
REPO_NAME = "django-DefectDojo"
GITHUB_USER_NAME_TO_SLACK_EMAIL = {
    "Maffooch": "cody@defectdojo.com",
    "mtesauro": "matt@defectdojo.com",
    "devGregA": "greg@defectdojo.com",
    "blakeaowens": "blake@defectdojo.com",
    "dogboat": "sean@defectdojo.com",
    "cneill": "charles@defectdojo.com",
    "hblankenship": "harold@defectdojo.com",
}


# Helper function to calculate the prior Thursday from a given date
def get_prior_thursday(date: datetime) -> str:
    # Calculate the day of the week (0=Monday, 1=Tuesday, ..., 6=Sunday)
    weekday = date.weekday()
    # If today is Thursday (weekday 3), return the same day.
    if weekday == 3:
        return date
    # Calculate how many days to subtract to reach the most recent Thursday
    days_to_subtract = (
        weekday - 3
    ) % 7  # (weekday - 3) gives the number of days past Thursday
    prior_thursday = date - timedelta(days=days_to_subtract)

    return prior_thursday.strftime("%Y-%m-%d")


# Helper function to get Slack User ID from Slack Email
def get_slack_user_id(slack_email: str) -> int:
    headers = {"Authorization": f"Bearer {SLACK_TOKEN}"}
    params = {"email": slack_email}
    response = requests.get(
        "https://slack.com/api/users.lookupByEmail", headers=headers, params=params
    )

    if response.status_code != 200 or not response.json().get("ok"):
        print(f"Error fetching Slack user ID for email {slack_email}: {response.text}")
        return None

    slack_user_id = response.json().get("user", {}).get("id")
    return slack_user_id


# Helper function to fetch pull requests from GitHub
def get_pull_requests() -> dict:
    headers = {"Authorization": f"token {GH_TOKEN}"}
    response = requests.get(
        f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/pulls", headers=headers
    )

    if response.status_code != 200:
        print(f"Error fetching PRs: {response.text}")
        response.raise_for_status()

    return response.json()


# Helper function to get PR reviews (approved, changes requested, or pending)
def get_pr_reviews(pull_request: dict) -> list[dict]:
    pr_number = pull_request["number"]
    reviews_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}/reviews"
    headers = {"Authorization": f"token {GH_TOKEN}"}
    response = requests.get(reviews_url, headers=headers)

    if response.status_code != 200:
        print(f"Error fetching reviews for PR {pr_number}: {response.text}")
        return []

    reviews = response.json()
    # Dictionary to store the latest review for each user
    latest_reviews = {}
    # Iterate over each review to find the latest one for each user
    for review in reviews:
        user = review["user"]["login"]
        submitted_at = review["submitted_at"]
        state = review["state"]
        # Convert the submitted_at timestamp to a datetime object for comparison
        review_time = datetime.strptime(submitted_at, "%Y-%m-%dT%H:%M:%SZ")
        # If the user doesn't have a review or the current one is later, update
        if (
            user not in latest_reviews
            or review_time > latest_reviews[user]["submitted_at"]
            and state != "COMMENTED"
        ):
            latest_reviews[user] = {
                "user": user,
                "state": state,
                "submitted_at": review_time,
                "url": review["html_url"],
            }
    # Determine if there are any pending reviewers
    latest_reviews.update(
        {
            user_dict.get("login"): {
                "user": user_dict.get("login"),
                "state": "PENDING",
            }
            for user_dict in pull_request.get("requested_reviewers", [])
        }
    )
    # Return the latest review state and URL for each user
    return latest_reviews.values()


# Helper function to send a message via Slack
def send_slack_message(slack_user_id: int, message: str) -> None:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {SLACK_TOKEN}",
    }
    payload = {"channel": slack_user_id, "text": message}
    response = requests.post(
        "https://slack.com/api/chat.postMessage", json=payload, headers=headers
    )

    if response.status_code != 200 or not response.json().get("ok"):
        print(f"Error sending Slack message: {response.text}")
        response.raise_for_status()


# Helper function to format the PR message with review statuses
def format_pr_message(pull_request: dict, reviews: list[dict]) -> str:
    repo_name = pull_request["head"]["repo"]["name"]
    pull_request_title = pull_request["title"]
    pull_request_url = pull_request["html_url"]
    pull_request_number = pull_request["number"]
    constructed_title = f"{repo_name} (#{pull_request_number}): {pull_request_title}"
    message = f"• <{pull_request_url}|{constructed_title}>"
    # Fetch the milestone due date and URL
    if (milestone := pull_request.get("milestone")) is not None and (
        (milestone_due_date := milestone.get("due_on"))
        and (milestone_url := milestone.get("html_url"))
        and (milestone_title := milestone.get("title"))
    ):
        message += f"\n    Merge by: {get_prior_thursday(datetime.strptime(milestone_due_date, '%Y-%m-%dT%H:%M:%SZ'))} for release <{milestone_url}|{milestone_title}>"
    # Format reviews and append to the message (only latest review status per user)
    message += "\n    Review Status:\n"
    for review in reviews:
        user = review["user"]
        state = review["state"]
        if url := review.get("url"):
            message += f"    • {user}: <{url}|{state.lower().capitalize()}>\n"
        else:
            message += f"    • {user}: {state.lower().capitalize()}\n"

    return message


# Main function to process PRs and notify Slack users
def notify_reviewers():
    try:
        user_pr_map = {}
        slack_email_to_slack_id = {}
        pull_requests = get_pull_requests()
        # Logging all fetched PR details
        print(f"Fetched {len(pull_requests)} PRs from GitHub.")
        for pull_request in pull_requests:
            title = pull_request["title"]
            pr_number = pull_request["number"]
            print(f"Processing PR: {pr_number} - {title}")
            reviews = get_pr_reviews(pull_request)
            print(f"Found {len(reviews)} reviews for PR {pr_number}.")
            message = format_pr_message(pull_request, reviews)
            # Map Slack users to PR messages
            for review in reviews:
                github_username = review["user"]
                if github_username not in user_pr_map:
                    user_pr_map[github_username] = ""
                # Determine if we should prune any non pending reviews
                if f"{github_username}: Pending" in message:
                    user_pr_map[github_username] += message + "\n"
        # Add the Header at the beginning of the list
        header_message = "Here are the PRs that are still requiring review:"
        # Add Tips and Tricks at the end of the list
        tips_message = "*Tips and Tricks*\n"
        tips_message += (
            "• This is how to remove a PR from the list: Approve, Request changes, or leave a general comment.\n"
            "• If someone else has requested changes, then leave a general comment to remove the pending review from yourself."
        )
        # Send Slack messages to reviewers
        for github_username, pr_list in user_pr_map.items():
            if pr_list:
                if slack_email := GITHUB_USER_NAME_TO_SLACK_EMAIL.get(github_username):
                    if slack_user_id := slack_email_to_slack_id.get(
                        slack_email, get_slack_user_id(slack_email)
                    ):
                        message_content = f"Hello {github_username}! {header_message}\n{pr_list}\n{tips_message}"
                        # print("\n\n", message_content, "\n\n")
                        send_slack_message(slack_user_id, message_content)
    except Exception as e:
        print(f"Error occurred: {e}")
        raise


if __name__ == "__main__":
    notify_reviewers()
