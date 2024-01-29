import hashlib
import hmac
import json
import os
import requests
import re
from jira import JIRA



def verify_github_webhook(event, context):
    # Replace 'YOUR_GITHUB_SECRET' with your actual GitHub webhook secret
    github_secret = os.environ.get('github_secret')

    if github_secret is None:
        return {
            'statusCode': 500,
            'body': 'GitHub secret is not configured.'
        }

    # Get the request headers and payload
    
    print(json.dumps(event, indent=2))  # Print the entire event for inspection
    
    # Access individual headers from the 'headers' object
    headers = event.get('headers', {})
    print("Headers:", headers)
    
    body = event.get('body', {})
    print("Body:", body)

    # Check if the 'x-Hub-Signature' header is present
    if 'X-Hub-Signature' not in headers:
        return {
            'statusCode': 400,
            'body': 'X-Hub-Signature header is missing.'
        }

    # Retrieve the signature from the headers
    provided_signature = headers['X-Hub-Signature']

    # Calculate the expected signature using the secret and payload
    expected_signature = 'sha1=' + hmac.new(
        github_secret.encode('utf-8'),
        body.encode('utf-8'),  # Use 'body' instead of 'payload'
        hashlib.sha1
    ).hexdigest()

    # Compare the provided signature with the expected signature
    if not hmac.compare_digest(provided_signature, expected_signature):
        return {
            'statusCode': 403,
            'body': 'Signature verification failed.'
        }

    return {
        'statusCode': 200,
        'body': 'GitHub webhook connection verified.'
    }

def create_jira_ticket(event, context):
    # Replace 'YOUR_JIRA_API_ENDPOINT', 'YOUR_JIRA_USERNAME', and 'YOUR_JIRA_PASSWORD' with your Jira details
    jira_api_endpoint = os.environ.get('jira_api_endpoint')
    jira_username = os.environ.get('jira_username')
    jira_password = os.environ.get('jira_password')
    project_key = os.environ.get('project_key')
    
    try:
        # Initialize a Jira object with your API credentials and server URL
        jira = JIRA(server=jira_api_endpoint, basic_auth=(jira_username, jira_password))
        
        # Parse the GitHub webhook payload JSON
        print(json.dumps(event, indent=2))
        github_payload = json.loads(event.get('body', '{}'))  # Parse 'body' as JSON

        # Extract relevant information from the GitHub payload
        # You may need to adjust this based on your specific use case
        repo_name = github_payload.get('repository', {}).get('name')
        event_type = github_payload.get('action')
        issue_title = github_payload.get('issue', {}).get('title')
        issue_url = github_payload.get('issue', {}).get('html_url')

        # Create a Jira ticket based on the GitHub update
        jira_data = {
            'project': {'key': project_key},  # Replace with your Jira project key
            'summary': f'GitHub Update for {repo_name} - {event_type}: {issue_title}',
            'description': f'GitHub Issue URL: {issue_url}',
            'issuetype': {'name': 'Task'}  # You can choose the appropriate issue type
        }

        # Make a POST request to create the Jira ticket
        issue = jira.create_issue(**jira_data)

        return {
            'statusCode': 200,
            'body': f'Jira ticket created successfully. Issue Key: {issue.key}'
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': f'Error creating Jira ticket: {str(e)}'
        }

def lambda_handler(event, context):
    # Call both functions
    result1 = verify_github_webhook(event, context)
    result2 = create_jira_ticket(event, context)

    # You can choose how to handle the results or combine them as needed
    combined_result = {
        'verify_github_webhook_result': result1,
        'create_jira_ticket_result': result2
    }

    return {
        'statusCode': 200,
        'body': json.dumps(combined_result),
        'headers': {
            'Content-Type': 'application/json'
         }
    }
