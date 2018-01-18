#!/usr/bin/env python
# -*- coding: utf-8 -*-

import shutil
import sys
import math
import datetime
import argparse
import tempfile
import os
import re
import json
import stat
from defaultRegexes.regexChecks import regexes
from git import Repo
from urllib.parse import urlparse

def main():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git (or just in a local directory).')
    parser.add_argument('--json', dest="output_json", action="store_true", help="Output in JSON")
    parser.add_argument("--skip_regex", dest="skip_regex", action="store_true", help="Skips the regex checks")
    parser.add_argument("--skip_entropy", dest="skip_entropy", action="store_true", help="Skips the entropy checks")
    parser.add_argument("--rules", dest="rules", help="Ignore default regexes and source from json list file")
    parser.add_argument("--since_commit", dest="since_commit", help="Only scan from a given commit hash")
    parser.add_argument("--max_depth", dest="max_depth", help="The max commit depth to go back when searching for secrets")
    parser.add_argument("--reduce_output", dest="to_reduce_output", action="store_true", help="Do not output the full file text for local searches")
    # parser.add_argument('git_url', type=str, help='URL for secret searching')
    parser.add_argument('source_location', type=str, help='Local path or Git URL to search')
    parser.set_defaults(skip_regex=False)
    parser.set_defaults(skip_entropy=False)
    parser.set_defaults(rules={})
    parser.set_defaults(max_depth=1000000)
    parser.set_defaults(since_commit=None)
    parser.set_defaults(entropy=True)
    parser.set_defaults(reduce_output=False)
    args = parser.parse_args()

    rules = {}
    if args.rules:
        try:
            with open(args.rules, "r") as ruleFile:
                rules = json.loads(ruleFile.read())
                for rule in rules:
                    rules[rule] = re.compile(rules[rule])
        except (IOError, ValueError) as e:
            raise("Error reading rules file")
        for regex in dict(regexes):
            del regexes[regex]
        for regex in rules:
            regexes[regex] = rules[regex]

    url = urlparse(args.source_location)
    if not url.scheme:
        output = find_strings_in_dir(args.source_location, not args.skip_regex, not args.skip_entropy, args.to_reduce_output)
    else:
        output = find_strings(args.source_location, args.since_commit, args.max_depth, args.output_json, not args.skip_regex, not args.skip_entropy)
        project_path = output["project_path"]
        shutil.rmtree(project_path, onerror=del_rw)
    
    print_results(args.output_json, output)

def str2bool(v):
    if v == None:
        return True
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)

def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def clone_git_repo(git_url):
    project_path = tempfile.mkdtemp()
    Repo.clone_from(git_url, project_path)
    return project_path

def print_results(printJson, output):

    if printJson:
        # print(json.dumps(issue, sort_keys=True, indent=4))
        print(json.dumps(output, indent=4))
    else:
        for issue in output["foundIssues"]:
            print("~~~~~~~~~~~~~~~~~~~~~")
            print_diff = issue.pop('printDiff', None)
            for key, value in issue.items():
                key_str = key.capitalize()
                value_str = value if sys.version_info >= (3, 0) else value.encode('utf-8')
                print("{}{}: {}{}".format(bcolors.OKGREEN, key_str, value_str, bcolors.ENDC))
            if print_diff:
                print(print_diff)
            print("~~~~~~~~~~~~~~~~~~~~~")

# def find_entropy(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash):
def find_entropy(printableDiff, issue_template, to_reduce_output=False):
    issue_template['reason'] = "High Entropy"

    issue = None
    strings_found = []
    marked_lines = []

    lines = printableDiff.split("\n")
    for i, line in enumerate(lines):
        for word in line.split():
            base64_strings = get_strings_of_set(word, BASE64_CHARS)
            hex_strings = get_strings_of_set(word, HEX_CHARS)
            for string in base64_strings:
                b64Entropy = shannon_entropy(string, BASE64_CHARS)
                if b64Entropy > 4.5:
                    strings_found.append(string)
                    marked_lines.append(label_line(i + 1, line))
                    if not to_reduce_output:
                        printableDiff = printableDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)
            for string in hex_strings:
                hexEntropy = shannon_entropy(string, HEX_CHARS)
                if hexEntropy > 3:
                    strings_found.append(string)
                    marked_lines.append(label_line(i + 1, line))
                    if not to_reduce_output:
                        printableDiff = printableDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)

    if strings_found:
        issue = issue_template.copy()
        issue['the_marked_lines'] = marked_lines

        if not to_reduce_output:
            issue['strings_found'] = strings_found
            issue['printDiff'] = printableDiff

    return issue

# def regex_check(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash):
def regex_check(printableDiff, issue_template, to_reduce_output=False):
    regex_matches = []

    for key in regexes:
        marked_lines = []
        strings_found = regexes[key].findall(printableDiff)

        for found_string in strings_found:
            if not to_reduce_output:
                found_diff = printableDiff.replace(found_string, bcolors.WARNING + found_string + bcolors.ENDC)
            marked_lines += get_marked_lines(printableDiff, found_string)

        if strings_found:
            issue = issue_template.copy()
            issue['reason'] = key
            issue['the_marked_lines'] = marked_lines

            if not to_reduce_output:
                issue['strings_found'] = strings_found
                issue['printDiff'] = found_diff

            regex_matches.append(issue)

    return regex_matches

def get_marked_lines(text, token):
    marked_lines = []

    lines = text.split("\n")
    for i, line in enumerate(lines):
        if token in line:
            marked_lines.append(label_line(i + 1, line))

    return marked_lines

def label_line(line_number, line):
    return '{}: {}'.format(line_number, line)


def find_strings_in_dir(directory, do_regex, do_entropy, to_reduce_output):
# From Runako
    output = {"foundIssues": [], "skippedFiles": []}

    for root, subdirs, files in os.walk(directory):
        files = [f for f in files if not f == '.gitignore']
        subdirs[:] = [d for d in subdirs if not d[0] == '.']
        for f in files:
            full_path = os.path.join(root, f)

            # Chop the directory from the left.
            display_path = full_path[len(directory) + 1 :]

            # try:
            try:
                text = open(full_path, 'r').read()
            except (UnicodeDecodeError):
                # print("Skipping " + full_path + " (trouble decoding file)")
                output["skippedFiles"].append(full_path)
                continue
                # text = open(full_path, 'r', -1, 'latin-1').read()
            # except:
            #     print("Skipping " + full_path + " (trouble decoding file)")
            #     continue

            found_issues = find_strings_in_text(text, display_path, do_regex, do_entropy, to_reduce_output)
            output["foundIssues"] += found_issues
    
    return output

def find_strings_in_text(text, title, do_regex, do_entropy, to_reduce_output):
    issue_template = {"path": title}
    found_issues = []

    if do_entropy:
        entropicDiff = find_entropy(text, issue_template.copy(), to_reduce_output)
        if entropicDiff:
            found_issues.append(entropicDiff)

    if do_regex:
        found_regexes = regex_check(text, issue_template.copy(), to_reduce_output)
        found_issues += found_regexes

    return found_issues

def find_strings(git_url, since_commit, max_depth, printJson, do_regex, do_entropy):
    output = {"foundIssues": []}
    project_path = clone_git_repo(git_url)
    repo = Repo(project_path)
    already_searched = set()

    for remote_branch in repo.remotes.origin.fetch():
        since_commit_reached = False
        branch_name = remote_branch.name.split('/')[1]
        try:
            repo.git.checkout(remote_branch, b=branch_name)
        except:
            pass

        prev_commit = None
        for curr_commit in repo.iter_commits(max_count=max_depth):
            commitHash = curr_commit.hexsha
            if commitHash == since_commit:
                since_commit_reached = True
            if since_commit and since_commit_reached:
                prev_commit = curr_commit
                continue
            if not prev_commit:
                pass
            else:
                #avoid searching the same diffs
                hashes = str(prev_commit) + str(curr_commit)
                if hashes in already_searched:
                    prev_commit = curr_commit
                    continue
                already_searched.add(hashes)

                diff = prev_commit.diff(curr_commit, create_patch=True)
                for blob in diff:
                    printableDiff = blob.diff.decode('utf-8', errors='replace')
                    if printableDiff.startswith("Binary files"):
                        continue
                    commit_time =  datetime.datetime.fromtimestamp(prev_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')

                    issue_template = {}
                    issue_template['date'] = commit_time
                    issue_template['path'] = blob.b_path if blob.b_path else blob.a_path
                    issue_template['branch'] = branch_name
                    issue_template['commit'] = prev_commit.message
                    issue_template['diff'] = blob.diff.decode('utf-8', errors='replace')
                    issue_template['commitHash'] = commitHash

                    foundIssues = []
                    if do_entropy:
                        # entropicDiff = find_entropy(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash)
                        entropicDiff = find_entropy(printableDiff, issue_template.copy())
                        if entropicDiff:
                            foundIssues.append(entropicDiff)
                    if do_regex:
                        # found_regexes = regex_check(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash)
                        found_regexes = regex_check(printableDiff, issue_template.copy())
                        foundIssues += found_regexes
                    # for foundIssue in foundIssues:
                    #     print_results(printJson, foundIssue)
                    output["foundIssues"] += foundIssues

            prev_commit = curr_commit
    output["project_path"] = project_path 
    output["clone_uri"] = git_url 
    return output

if __name__ == "__main__":
    main()
