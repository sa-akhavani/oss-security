import os
import csv
import datetime
from git import Repo
from concurrent.futures import ThreadPoolExecutor
import threading


REPO_BASE_PATH = "./repos"
RESULT_CSV_PATH = "./contributor_history_results.csv"
REPO_LIST_PATH = "../datasets/processed_git_details.csv"
BATH_SIZE = 20
PROCESS_COUNT = 10


# Period definition. Two datapoints per year from 2017 to 2025, January 1st to June 30th and July 1st to December 31st
periods = [
        {'since': '2017-01-01', 'until': '2017-06-30'},
        {'since': '2017-07-01', 'until': '2017-12-31'},
        {'since': '2018-01-01', 'until': '2018-06-30'},
        {'since': '2018-07-01', 'until': '2018-12-31'},
        {'since': '2019-01-01', 'until': '2019-06-30'},
        {'since': '2019-07-01', 'until': '2019-12-31'},
        {'since': '2020-01-01', 'until': '2020-06-30'},
        {'since': '2020-07-01', 'until': '2020-12-31'},
        {'since': '2021-01-01', 'until': '2021-06-30'},
        {'since': '2021-07-01', 'until': '2021-12-31'},
        {'since': '2022-01-01', 'until': '2022-06-30'},
        {'since': '2022-07-01', 'until': '2022-12-31'},
        {'since': '2023-01-01', 'until': '2023-06-30'},
        {'since': '2023-07-01', 'until': '2023-12-31'},
        {'since': '2024-01-01', 'until': '2024-06-30'},
        {'since': '2024-07-01', 'until': '2024-12-31'},
]

lock = threading.Lock()  # For thread-safe writing to CSV

def clone_or_open_repo(repo_url, repo_name):
    """
    Clone the repository if it does not exist locally. Otherwise, open the existing repository.
    """
    repo_path = os.path.join(REPO_BASE_PATH, repo_name)

    if not os.path.exists(repo_path):
        print(f"Cloning {repo_url}...")
        repo = Repo.clone_from(repo_url, repo_path)
    else:
        print(f"Opening existing repository: {repo_name}")
        repo = Repo(repo_path)
    
    return repo

def get_commits_for_period(repo, since_date, until_date):
    """
    Get all commits within a specific date range.
    """
    since_date_str = since_date.strftime('%Y-%m-%d')
    until_date_str = until_date.strftime('%Y-%m-%d')
    commits = list(repo.iter_commits(since=since_date_str, until=f"{until_date_str}T23:59:59"))
    return commits

def fetch_unique_contributors(commits):
    """
    Count the unique contributors in the list of commits.
    """
    contributors = set()
    for commit in commits:
        contributors.add(commit.author.email)
    return contributors

def process_repo(row):
    """
    Process a repository to get the number of unique contributors for each period and cumulative contributors until the end of that time.
    """
    repo_url = row['GitHub URL']
    repo_id = row['ID']

    repo_data = []

    try :
        repo_name = repo_url.rstrip('/').split('/')[-1]  # Extract the repo name from URL
        # clone or open repo
        repo = clone_or_open_repo(repo_url, repo_name)

        # process each period and sum up the contributors
        cumulative_contributors = set()

        # process each period and sum up the contributors
        for period in periods:
            since_date = datetime.datetime.strptime(period['since'], '%Y-%m-%d')
            until_date = datetime.datetime.strptime(period['until'], '%Y-%m-%d')
            commits = get_commits_for_period(repo, since_date, until_date)
            period_contributors = fetch_unique_contributors(commits)
            cumulative_contributors = cumulative_contributors.union(period_contributors)

            contributors = len(period_contributors)
            cumulative = len(cumulative_contributors)

            period_data = [repo_id, repo_name, repo_url, since_date, until_date, contributors, cumulative]
            repo_data.append(period_data)
        return repo_data

    except Exception as e:
        print(f"Error processing repository {repo_url}: {e}")
        return []

def save_results(results):
    """
    Save the processed results to the CSV file in a thread-safe manner.
    """
    with lock:
        with open(RESULT_CSV_PATH, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(results)

def process_repos(input_csv_path):
    """
    Process all repositories in the list using 10 threads concurrently.
    Save data in batches after processing 100 repos.
    """
    with open(input_csv_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        batch_results = []
        repo_count = 0

        # Use ThreadPoolExecutor to process repositories concurrently
        with ThreadPoolExecutor(max_workers=PROCESS_COUNT) as executor:
            futures = []
            
            for row in reader:
                # Submit the task for processing the repository
                futures.append(executor.submit(process_repo, row))
                repo_count += 1

                if repo_count % BATH_SIZE == 0:
                    # Collect results from all futures in this batch
                    for future in futures:
                        repo_results = future.result()
                        batch_results.extend(repo_results)
                    
                    # Save batch results to file
                    save_results(batch_results)
                    batch_results = []  # Reset the batch
                    futures = []  # Reset futures list
                    print(f"Processed {repo_count} repositories, results saved.")
                    # sleep for 30 secs
                    time.sleep(30)

            # Collect and save remaining results
            for future in futures:
                repo_data = future.result()
                batch_results.extend(repo_data)
            if batch_results:
                save_results(batch_results)
                print(f"Final batch saved. Total repositories processed: {repo_count}")
  


def read_repo_list(repo_list_path):
    """
    Read the input CSV file and extract necessary information.
    this is the csv format:
    ID,GITHUB_URL,PERIOD_START,PERIOD_END,CONTRIBUTORS,CUMULATIVE_CONTRIBUTORS
    """
    with open(repo_list_path, 'r') as f:
        repos = [line.strip() for line in f.readlines() if line.strip()]
    return repos


def write_results(result_csv_path, extracted_data):
    """
    Initialize the result CSV file and write headers.
    """
    with open(result_csv_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["REPO_NAME", "GITHUB_URL", "PERIOD_START", "PERIOD_END", "CONTRIBUTORS", "CUMULATIVE_CONTRIBUTORS"])


if __name__ == "__main__":
    # Initialize the result CSV with headers
    write_results(RESULT_CSV_PATH, [])
    # Process the repositories
    extracted_data = process_repos(REPO_LIST_PATH)

    print("Processing completed.")
