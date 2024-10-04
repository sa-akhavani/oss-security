import requests
from collections import defaultdict

# GITHUB_TOKEN = 'your_github_token'
# headers = {'Authorization': f'token {GITHUB_TOKEN}'}
headers = {}

def get_commits(owner, repo, since, until):
    url = f'https://api.github.com/repos/{owner}/{repo}/commits'
    params = {'since': since, 'until': until}
    response = requests.get(url, headers=headers, params=params)
    return response.json()

def extract_unique_contributors(commits):
    unique_contributors = set()
    for commit in commits:
        if commit.get('author'):
            unique_contributors.add(commit['author']['login'])
    return unique_contributors

def get_unique_contributors_over_time(owner, repo, periods):
    unique_contributors_count = defaultdict(int)
    all_contributors = set()

    for period in periods:
        commits = get_commits(owner, repo, period['since'], period['until'])
        contributors = extract_unique_contributors(commits)
        all_contributors.update(contributors)
        unique_contributors_count[period['until']] = len(all_contributors)

    return unique_contributors_count

# Example usage
periods = [
    {'since': '2024-01-01T00:00:00Z', 'until': '2024-06-30T23:59:59Z'},
    {'since': '2024-07-01T00:00:00Z', 'until': '2024-12-29T23:59:59Z'},
    {'since': '2023-01-01T00:00:00Z', 'until': '2023-06-30T23:59:59Z'},
    {'since': '2023-07-01T00:00:00Z', 'until': '2023-12-29T23:59:59Z'},
    # 2022
    {'since': '2022-01-01T00:00:00Z', 'until': '2022-06-30T23:59:59Z'},
    {'since': '2022-07-01T00:00:00Z', 'until': '2022-12-31T23:59:59Z'},
    # 2021
    {'since': '2021-01-01T00:00:00Z', 'until': '2021-06-30T23:59:59Z'},
    {'since': '2021-07-01T00:00:00Z', 'until': '2021-12-31T23:59:59Z'},
    # 2020
    {'since': '2020-01-01T00:00:00Z', 'until': '2020-06-30T23:59:59Z'},
    {'since': '2020-07-01T00:00:00Z', 'until': '2020-12-31T23:59:59Z'},
    # 2019
    {'since': '2019-01-01T00:00:00Z', 'until': '2019-06-30T23:59:59Z'},
    {'since': '2019-07-01T00:00:00Z', 'until': '2019-12-31T23:59:59Z'},
    # 2018
    {'since': '2018-01-01T00:00:00Z', 'until': '2018-06-30T23:59:59Z'},
    {'since': '2018-07-01T00:00:00Z', 'until': '2018-12-31T23:59:59Z'},
    # 2017
    {'since': '2017-01-01T00:00:00Z', 'until': '2017-06-30T23:59:59Z'},
    {'since': '2017-07-01T00:00:00Z', 'until': '2017-12-31T23:59:59Z'},
]

owner = 'expressjs'
repo = 'express'

contributors_data = get_unique_contributors_over_time(owner, repo, periods)
print(contributors_data)

