# A quick CLI tool to patch a Chrome extension policy for a Google workspace orgunit.
#
# Used these for reference:
# https://developers.google.com/chrome/policy/guides/app-samples
# https://developers.google.com/chrome/policy/reference/rest/v1/customers.policies/resolve
# https://github.com/alextcowan/chrome-policy-api-quickstart/blob/main/chrome_policy_api_qs.py
# https://developers.google.com/chrome/policy/guides/samples
import argparse
import json
import os

from google.oauth2 import credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build


# If modifying these scopes, delete the file token.json.
SCOPES = [
    #'https://www.googleapis.com/auth/chrome.management.policy.readonly',
    "https://www.googleapis.com/auth/chrome.management.policy",
]


def init_creds(credentials_file):
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists("token.json"):
        creds = credentials.Credentials.from_authorized_user_file("token.json", SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds


def main():
    parser = argparse.ArgumentParser(
        description="Change Chrome extension policy (chrome.users.apps.ManagedConfiguration) for an orgunit."
    )
    parser.add_argument("--orgunit", required=True, help="OU id (find it on admin.google.com)")
    parser.add_argument(
        "--extension_id", required=True, help="The ID of the extension."
    )
    parser.add_argument(
        "--credentials_file",
        required=True,
        help="Path to the OAuth2 credentials JSON file (downloaded from Google Cloud Console).",
    )
    args = parser.parse_args()
    creds = init_creds(args.credentials_file)
    service = build("chromepolicy", "v1", credentials=creds)

    policyTargetKey = {
        "targetResource": f"orgunits/{args.orgunit}",
        "additionalTargetKeys": {"app_id": f"chrome:{args.extension_id}"},
    }
    body = dict(
        policyTargetKey=policyTargetKey,
        policySchemaFilter="chrome.users.apps.ManagedConfiguration",
    )
    request = (
        service.customers()
        .policies()
        .resolve(customer="customers/my_customer", body=body)
    )
    response = request.execute()
    print(json.dumps(response, indent=2))
    cfg = json.loads(
        response["resolvedPolicies"][0]["value"]["value"]["managedConfiguration"]
    )

    # TODO: Edit the configuration

    body = {
        "requests": [
            dict(
                updateMask={"paths": ["managedConfiguration"]},
                policyTargetKey=policyTargetKey,
                policyValue={
                    "policySchema": "chrome.users.apps.ManagedConfiguration",
                    "value": {"managedConfiguration": json.dumps(cfg, indent=2)},
                },
            )
        ]
    }
    request = (
        service.customers()
        .policies()
        .orgunits()
        .batchModify(customer="customers/my_customer", body=body)
    )
    response = request.execute()
    print(json.dumps(response, indent=2))


if __name__ == "__main__":
    main()
