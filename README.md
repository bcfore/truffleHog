# BCF Trufflehog

## Overview

I've modified [the original Trufflehog](https://github.com/dxa4481/truffleHog)
to allow scanning local directories, without scanning the entire git history.

The core changes I copied from [Runako's fork of Trufflehog](https://github.com/runako/truffleHog/tree/rg-local-scan)
(the `rg-local-scan` branch). But Trufflehog has been updated significantly since Runako's fork, so it required quite a
bit of tinkering to get the local-scan version working again.

I was using Python 3.6. I doubt it works on Python 2.X (I didn't test).

I didn't mess too much with the code that scans git histories.
(I was mainly concerned with just scanning the directory.)
In particular,
I didn't implement the `--reduce_output` option for that, so expect a _lot_ of
output if you run the git-scan version.

## Usage

From within the Trufflehog root directory, you can run it like this:

```shell
python3 ./truffleHog/truffleHog.py --json --reduce_output ../../../../code_review/company_name/project_folder
```

If you leave off the `--reduce_output` flag, it'll give the full text of the flagged files in the output.

You can still check the full git history for a local path. For that, call it like this:

```shell
python3 ./truffleHog/truffleHog.py --json --since_commit xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx file:///Users/username/Documents/code_review/company_name/project_folder
```

I included the `--since_commit` flag but you can leave that off. (It might take awhile before you get the results though,
depending on how far back your git history goes.)

## Regex checks

You can modify the regex checks by editing the `regexChecks.py` file (or by passing in your own regex file, as he
discusses below, though I didn't check that).

## Skipped files

You may notice that some files are skipped (they are listed in the output json).
It's because there was a problem decoding the file in this line:

```python
text = open(full_path, 'r').read()
```

If you want you can try opening them with a different encoding, e.g.:

```python
text = open(full_path, 'r', -1, 'latin-1').read()
```

## Help output

```shell
usage: truffleHog.py [-h] [--json] [--skip_regex] [--skip_entropy]
                     [--rules RULES] [--since_commit SINCE_COMMIT]
                     [--max_depth MAX_DEPTH] [--reduce_output]
                     source_location

Find secrets hidden in the depths of git (or just in a local directory).

positional arguments:
  source_location       Local path or Git URL to search

optional arguments:
  -h, --help            show this help message and exit
  --json                Output in JSON
  --skip_regex          Skips the regex checks
  --skip_entropy        Skips the entropy checks
  --rules RULES         Ignore default regexes and source from json list file
  --since_commit SINCE_COMMIT
                        Only scan from a given commit hash
  --max_depth MAX_DEPTH
                        The max commit depth to go back when searching for
                        secrets
  --reduce_output       Do not output the full file text for local searches
```

Following is the original documentation for Trufflehog.

## Truffle Hog (original documentation)
Searches through git repositories for secrets, digging deep into commit history and branches. This is effective at finding secrets accidentally committed.

### NEW
Trufflehog previously functioned by running entropy checks on git diffs. This functionality still exists, but high signal regex checks have been added, and the ability to surpress entropy checking has also been added.

These features help cut down on noise, and makes the tool easier to shove into a devops pipeline.


```
truffleHog --regex --entropy=False https://github.com/dxa4481/truffleHog.git
```

or

```
truffleHog file:///user/dxa4481/codeprojects/truffleHog/
```


### Install
```
pip install truffleHog
```

### Customizing

Custom regexes can be added to the following file:
```
truffleHog/truffleHog/regexChecks.py
```
Things like subdomain enumeration, s3 bucket detection, and other useful regexes highly custom to the situation can be added.

Feel free to also contribute high signal regexes upstream that you think will benifit the community. Things like Azure keys, Twilio keys, Google Compute keys, are welcome, provided a high signal regex can be constructed.

### How it works
This module will go through the entire commit history of each branch, and check each diff from each commit, and check for secrets. This is both by regex and by entropy. For entropy checks, trufflehog will evaluate the shannon entropy for both the base64 char set and hexidecimal char set for every blob of text greater than 20 characters comprised of those character sets in each diff. If at any point a high entropy string >20 characters is detected, it will print to the screen.

### Help

_Note: Following is the original version. BCF's version is different; see above._

```
Find secrets hidden in the depths of git.

positional arguments:
  git_url               URL for secret searching

optional arguments:
  -h, --help            show this help message and exit
  --json                Output in JSON
  --regex               Enable high signal regex checks
  --entropy DO_ENTROPY  Enable entropy checks
  --since_commit SINCE_COMMIT
                        Only scan from a given commit hash
  --max_depth MAX_DEPTH
                        The max commit depth to go back when searching for
                        secrets
```

### Wishlist

- ~~A way to detect and not scan binary diffs~~
- ~~Don't rescan diffs if already looked at in another branch~~
- ~~A since commit X feature~~
- ~~Print the file affected~~
