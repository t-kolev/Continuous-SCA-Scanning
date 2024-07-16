import argparse
import os
import json
import pprint
import re
from statistics import mean
from collections import Counter, defaultdict

import numpy as np
import matplotlib.pyplot as plt

# List to store repositories with errors
repoWithError = []

# Regular expressions to exclude certain packages in the RIC repositories
test_package = re.compile(r'test/')
benchmark_package = re.compile(r'benchmark')
examples_package = re.compile(r'examples/')
testapplication_package = re.compile(r'testapplication/')
cert_package = re.compile(r'certs/')

# Normalize the results from each tool
def format_sca_tool_data(repository, tool):
    if tool == "Grype.txt":
        return formatGrype(repository)
    elif tool == "Snyk.txt":
        return formatSnyk(repository)
    elif tool == "Trivy.txt":
        return formatTrivy(repository)

# Format the results from Grype tool
def formatGrype(repository):
    GrypeRepo = json.loads(repository)
    vulnArray = []
    for vuln in GrypeRepo["matches"]:
        path = vuln.get("artifact").get("locations")[0].get("path")
        if any([test_package.search(path), benchmark_package.search(path), examples_package.search(path), testapplication_package.search(path)]):
            continue
        vulnArray.append(vuln)
    return vulnArray

# Format the results from Snyk tool
def formatSnyk(repository):
    content = json.loads(repository)
    vulnArray = []
    if "error" not in content:
        for target in content:
            if not isinstance(target, str):
                vulnList = target.get('vulnerabilities')
                path = target.get('displayTargetFile')
                if any([test_package.search(path), benchmark_package.search(path), examples_package.search(path), testapplication_package.search(path)]):
                    continue
                for vuln in vulnList:
                    vuln.pop('semver', None)
                    vulnArray.append(vuln)
            else:
                if target == 'vulnerabilities':
                    vulnList = content.get('vulnerabilities')
                    path = content.get('displayTargetFile')
                    if any([test_package.search(path), benchmark_package.search(path), examples_package.search(path), testapplication_package.search(path)]):
                        continue
                    for vuln in vulnList:
                        vuln.pop('semver', None)
                        vulnArray.append(vuln)
    else:
        global repoWithError
        repoWithError.append(os.path.basename(content.get('path', 'unknown')))
    return vulnArray

# Format the results from Trivy tool
def formatTrivy(repository):
    index = repository.find("{")
    repo = repository[index:]
    TrivyRepo = json.loads(repo)
    results = TrivyRepo.get("Results")
    vulnArray = []
    if results is not None:
        for target in results:
            path = target.get("Target")
            if any([test_package.search(path), benchmark_package.search(path), examples_package.search(path)]):
                continue
            vulnTarget = target.get("Vulnerabilities", [])
            if not vulnTarget:
                continue
            for vuln in vulnTarget:
                vuln["Path"] = path
            vulnArray.extend(vulnTarget)
    return vulnArray

# Get vulnerabilities categorized by directories
def get_vulnerabilities_by_directory(data, tool):
    vulnerabilities_by_directory = defaultdict(list)

    if tool == "Grype.txt":
        formatted_data = format_sca_tool_data(data, "Grype.txt")
        for vuln in formatted_data:
            path = vuln.get("artifact").get("locations")[0].get("path")
            if any([test_package.search(path), benchmark_package.search(path), examples_package.search(path), testapplication_package.search(path)]):
                continue
            directory = path.split('/')[1]
            vulnerabilities_by_directory[directory].append(vuln)

    elif tool == "Trivy.txt":
        repo = json.loads(data)
        results = repo.get("Results")
        for vuln in results:
            path = vuln.get("Target")
            if any([test_package.search(path), benchmark_package.search(path), examples_package.search(path), cert_package.search(path)]):
                continue
            vulnTarget = vuln.get("Vulnerabilities", [])
            if not vulnTarget:
                continue
            for vuln in vulnTarget:
                vuln["Path"] = path
                directory = path.split('/')[0]
                vulnerabilities_by_directory[directory].append(vuln)

    elif tool == "Snyk.txt":
        content = json.loads(data)
        if "error" not in content:
            for target in content:
                if not isinstance(target, str):
                    vulnList = target.get('vulnerabilities')
                    path = target.get('displayTargetFile')
                    if any([test_package.search(path), benchmark_package.search(path), examples_package.search(path), testapplication_package.search(path)]):
                        print("Snyk: Skipping:" + path)
                        continue
                    for vuln in vulnList:
                        directory = path.split('/')[0]
                        vulnerabilities_by_directory[directory].append(vuln)
                else:
                    if target == 'vulnerabilities':
                        vulnList = content.get('vulnerabilities')
                        path = content.get('displayTargetFile')
                        print("Snyk path: {}".format(path))
                        if any([test_package.search(path), benchmark_package.search(path), examples_package.search(path), testapplication_package.search(path)]):
                            print("Snyk: Skipping:" + path)
                            continue
                        for vuln in vulnList:
                            directory = path.split('/')[0]
                            vulnerabilities_by_directory[directory].append(vuln)
    return vulnerabilities_by_directory

# Save vulnerabilities by directory
def save_vulnerabilities_by_directory(vulnerabilities_by_directory, tool, base_dir):
    for directory, vulnerabilities in vulnerabilities_by_directory.items():
        clean_directory = re.sub(r'[^a-zA-Z0-9_\-]', '', directory)
        dir_path = os.path.join(base_dir, clean_directory)
        os.makedirs(dir_path, exist_ok=True)
        filename = f"{tool}"
        filepath = os.path.join(dir_path, filename)
        with open(filepath, 'w') as json_file:
            json.dump(vulnerabilities, json_file, separators=(',', ':'))

# Function to gather repository names within each RIC directory
def gather_repositories(rics):
    repositories = {ric: [] for ric in rics}
    for ric in rics:
        ric_dir = f"./{ric}"
        if not os.path.exists(ric_dir):
            os.makedirs(ric_dir)
        for repository in sorted(os.listdir(ric_dir)):
            repositories[ric].append(repository)
    return repositories

# Dump scan results into a JSON file
def dump_scan_results(rics, sca_tools):
    scan_results = {ric: {} for ric in rics}
    repositories = gather_repositories(rics)

    for ric in rics:
        scan_results[ric] = {repo: {} for repo in repositories[ric]}

        for repository in scan_results[ric].keys():
            path_to_repository = os.path.join(f"./{ric}", repository)
            for sca_tool_file in sorted(os.listdir(path_to_repository)):
                if sca_tool_file in sca_tools:
                    sca_tool_file_path = os.path.join(path_to_repository, sca_tool_file)
                    with open(sca_tool_file_path) as file:
                        vuln = file.read()
                    scan_results[ric][repository][sca_tool_file] = vuln

    with open('sca_results.json', 'w') as file:
        json.dump(scan_results, file)

    print("Finished writing: 'sca_results.json'")
    return scan_results

# Extract CVEs and CVSS dependencies from the scan results
def get_cves_cvss_dependencies(sca_tool, sca_tool_data):
    cves_cvss_dependencies = []
    cves = []
    cvss = []
    packages = []
    if sca_tool == "Grype.txt":
        for vulnerability in sca_tool_data:
            if vulnerability.get("vulnerability").get("id") not in cves:
                cves.append(vulnerability.get("vulnerability").get("id"))
                cvss_info = vulnerability.get("vulnerability").get("cvss")
                if cvss_info and len(cvss_info) > 0:
                    cvss.append(cvss_info[0].get("metrics").get("baseScore"))
                else:
                    cvss.append(None)
                    print(f"Vulnerability without CVSS: {vulnerability.get('vulnerability').get('id')}")
                vulnerability_match_details = vulnerability.get("matchDetails")
                for match_detail in vulnerability_match_details:
                    if "package" in match_detail["searchedBy"].keys():
                        packages.append(match_detail["searchedBy"]["package"]["name"])
                    elif "Package" in match_detail["searchedBy"].keys():
                        packages.append(match_detail["searchedBy"]["Package"]["name"])
            else:
                continue
        cves_cvss_dependencies = [cves, cvss, packages]
        return cves_cvss_dependencies
    elif sca_tool == "Snyk.txt":
        for vulnerability in sca_tool_data:
            if len(vulnerability.get("identifiers").get("CVE")) == 0:
                continue
            else:
                if vulnerability.get("identifiers").get("CVE")[0] not in cves:
                    cves.append(vulnerability.get("identifiers").get("CVE")[0])
                    cvss.append(vulnerability.get("cvssScore"))
                    packages.append(vulnerability.get("moduleName"))
        cves_cvss_dependencies = [cves, cvss, packages]
        return cves_cvss_dependencies
    elif sca_tool == "Trivy.txt":
        for vulnerability in sca_tool_data:
            if vulnerability.get("VulnerabilityID") not in cves:
                if vulnerability.get("CVSS") is not None:
                    cves.append(vulnerability.get("VulnerabilityID"))
                    packages.append(vulnerability.get("PkgName"))
                    nvd = vulnerability.get("CVSS").get("nvd")
                    ghsa = vulnerability.get("CVSS").get("ghsa")
                    if nvd is not None:
                        cvss.append(nvd.get("V3Score"))
                        continue
                    elif ghsa is not None:
                        cvss.append(ghsa.get("V3Score"))
                        continue
                else:
                    print(f"Vulnerability without CVSS: {vulnerability.get('VulnerabilityID')}")
                    continue
        cves_cvss_dependencies = [cves, cvss, packages]
        return cves_cvss_dependencies
    else:
        print("Unknown tool")
    return cves_cvss_dependencies

# Extract CVEs from the scan results
def extract_cves(sca_results):
    sca_cvecvss_dependencies = dict.fromkeys(sca_results.keys())
    
    print("Finished reading the SCA results data.")
    
    for ric in sca_results.keys():
        sca_cvecvss_dependencies[ric] = dict.fromkeys(sca_results[ric].keys())
        for repository in sca_results[ric].keys():
            sca_cvecvss_dependencies[ric][repository] = dict.fromkeys(sca_results[ric][repository].keys())
            for sca_tool in sca_results[ric][repository].keys():
                sca_tool_data_str = sca_results[ric][repository][sca_tool]
                if sca_tool_data_str is not None:
                    try:
                        sca_tool_data = json.loads(sca_tool_data_str)
                        sca_cvecvss_dependencies[ric][repository][sca_tool] = get_cves_cvss_dependencies(sca_tool, sca_tool_data)
                        if len(sca_cvecvss_dependencies[ric][repository][sca_tool][0]) != len(sca_cvecvss_dependencies[ric][repository][sca_tool][1]):
                            print("More CVSS than CVE")
                    except json.JSONDecodeError:
                        print(f"Error decoding JSON for RIC: {ric}, Repository: {repository}, SCA_Tool: {sca_tool}")
                else:
                    print(f"NoneType found for RIC: {ric}, Repository: {repository}, SCA_Tool: {sca_tool}")
                    print(f"sca_tool_data_str: {sca_tool_data_str}")
    return sca_cvecvss_dependencies

# Count CVEs per repository and RIC
def count_cves(cve_data):
    print("Going to count CVEs per repo and per RIC")

    ric_cves = dict.fromkeys(cve_data.keys())

    for ric in cve_data.keys():
        total_ric_cves = []
        for repository in cve_data[ric].keys():
            total_repo_cves = []
            for sca_tool in cve_data[ric][repository].keys():
                if cve_data[ric][repository][sca_tool] is None or cve_data[ric][repository][sca_tool][0] is None:
                    print(f"NoneType found for RIC: {ric}, Repository: {repository}, SCA_Tool: {sca_tool}")
                    total_cve_count = 0
                else:
                    try:
                        total_cve_count = len(cve_data[ric][repository][sca_tool][0])
                    except TypeError as e:
                        print(f"NoneType found for RIC: {ric}, Repository: {repository}, SCA_Tool: {sca_tool}")
                        print(f"Exception: {e}")
                        total_cve_count = 0
                
                if cve_data[ric][repository][sca_tool] is not None and cve_data[ric][repository][sca_tool][0] is not None:
                    for cve in cve_data[ric][repository][sca_tool][0]:
                        if cve not in total_repo_cves:
                            total_repo_cves.append(cve)
            
            print("RIC: {}, Repository: {}, Total Repo CVEs: {}".format(ric, repository, len(total_repo_cves)))
            total_ric_cves.extend(total_repo_cves)
        
        ric_cves[ric] = total_ric_cves
    
    pprint.pprint(ric_cves)
    for ric in ric_cves.keys():
        print("RIC: {}, Total unique CVEs: {}".format(ric, len(ric_cves[ric])))

# Count CVEs per repository and tool
def per_repo_cve_count(cve_data):
    print("1. CVEs per RIC/repo/tool\n"
          "2. Total CVEs per RIC/repo with duplicates\n"
          "3. Total CVEs per RIC/repo without duplicates")
    
    cve_per_ric_repo_tool = {ric: {} for ric in cve_data.keys()}
    for ric in cve_data.keys():
        cve_per_ric_repo_tool[ric] = dict.fromkeys(cve_data[ric].keys())
        for repository in cve_data[ric].keys():
            cve_per_ric_repo_tool[ric][repository] = dict.fromkeys(cve_data[ric][repository].keys())
            for sca_tool in cve_data[ric][repository].keys():
                if cve_data[ric][repository][sca_tool] is None:
                        cve_per_ric_repo_tool[ric][repository][sca_tool] = 0
                else:
                        try:
                            cve_per_ric_repo_tool[ric][repository][sca_tool] = len(cve_data[ric][repository][sca_tool][0])
                        except TypeError as e:
                            print(f"NoneType found for RIC: {ric}, Repository: {repository}, SCA_Tool: {sca_tool}")
                            print(f"Exception: {e}")
                            cve_per_ric_repo_tool[ric][repository][sca_tool] = 0

    cve_per_ric_repo = {ric: {} for ric in cve_data.keys()}
    for ric in cve_data.keys():
        cve_per_ric_repo[ric] = dict.fromkeys(cve_data[ric].keys())
        for repository in cve_data[ric].keys():
            cve_list_with_dups = []
            cve_list_without_dups = []
            for sca_tool in cve_data[ric][repository].keys():  
                try:
                    for cve in cve_data[ric][repository][sca_tool][0]:
                        cve_list_with_dups.append(cve)
                        if cve not in cve_list_without_dups:
                            cve_list_without_dups.append(cve)
                except TypeError as e:
                    print(f"NoneType found for RIC: {ric}, Repository: {repository}, SCA_Tool: {sca_tool}")
                    print(f"Exception: {e}")
            cve_per_ric_repo[ric][repository] = [cve_list_with_dups, cve_list_without_dups]
    return cve_per_ric_repo_tool, cve_per_ric_repo

# Analyze the distribution of CVSS scores
def cvss_distribution(cvss_data):
    for ric in cvss_data.keys():
        total_cve_count = 0
        total_cvss_count = 0
        for repository in cvss_data[ric].keys():
            for sca_tool in cvss_data[ric][repository].keys():
                if cvss_data[ric][repository][sca_tool] is not None:
                    total_cve_count += len(cvss_data[ric][repository][sca_tool][0])
                    total_cvss_count += len(cvss_data[ric][repository][sca_tool][1])

    low_cvss_per_ric_repo = dict.fromkeys(cvss_data.keys())
    medium_cvss_per_ric_repo = dict.fromkeys(cvss_data.keys())
    high_cvss_per_ric_repo = dict.fromkeys(cvss_data.keys())
    critical_cvss_per_ric_repo = dict.fromkeys(cvss_data.keys())
    cve_per_ric_repo = dict.fromkeys(cvss_data.keys())
    none_counter = 0
    
    for ric in cvss_data.keys():
        low_cvss_per_ric_repo[ric] = dict.fromkeys(cvss_data[ric].keys())
        medium_cvss_per_ric_repo[ric] = dict.fromkeys(cvss_data[ric].keys())
        high_cvss_per_ric_repo[ric] = dict.fromkeys(cvss_data[ric].keys())
        critical_cvss_per_ric_repo[ric] = dict.fromkeys(cvss_data[ric].keys())
        cve_per_ric_repo[ric] = dict.fromkeys(cvss_data[ric].keys())
        
        for repository in cvss_data[ric].keys():
            low_cvss_per_ric_repo[ric][repository] = dict.fromkeys(cvss_data[ric][repository].keys())
            medium_cvss_per_ric_repo[ric][repository] = dict.fromkeys(cvss_data[ric][repository].keys())
            high_cvss_per_ric_repo[ric][repository] = dict.fromkeys(cvss_data[ric][repository].keys())
            critical_cvss_per_ric_repo[ric][repository] = dict.fromkeys(cvss_data[ric][repository].keys())
            cve_per_ric_repo[ric][repository] = dict.fromkeys(cvss_data[ric][repository].keys())
            
            low_cves = []
            medium_cves = []
            high_cves = []
            critical_cves = []
            cves = []
            
            for sca_tool in cvss_data[ric][repository].keys():
                if cvss_data[ric][repository][sca_tool] is not None and sca_tool != "Scantist.json":
                    for index, cvss in enumerate(cvss_data[ric][repository][sca_tool][1]):
                        cve = cvss_data[ric][repository][sca_tool][0][index]
                        if cvss is None:
                            none_counter += 1
                        elif 0.1 <= cvss <= 3.9:
                            if cve not in low_cves and cve not in medium_cves and cve not in high_cves and cve not in critical_cves:
                                low_cves.append(cve)
                            if cve not in cves:
                                cves.append(cve)
                        elif 4.0 <= cvss <= 6.9:
                            if cve not in low_cves and cve not in medium_cves and cve not in high_cves and cve not in critical_cves:
                                medium_cves.append(cve)
                            if cve not in cves:
                                cves.append(cve)
                        elif 7.0 <= cvss <= 8.9:
                            if cve not in low_cves and cve not in medium_cves and cve not in high_cves and cve not in critical_cves:
                                high_cves.append(cve)
                            if cve not in cves:
                                cves.append(cve)
                        elif 9.0 <= cvss <= 10.0:
                            if cve not in low_cves and cve not in medium_cves and cve not in high_cves and cve not in critical_cves:
                                critical_cves.append(cve)
                            if cve not in cves:
                                cves.append(cve)
            
            low_cvss_per_ric_repo[ric][repository] = [len(low_cves), low_cves]
            medium_cvss_per_ric_repo[ric][repository] = [len(medium_cves), medium_cves]
            high_cvss_per_ric_repo[ric][repository] = [len(high_cves), high_cves]
            critical_cvss_per_ric_repo[ric][repository] = [len(critical_cves), critical_cves]
            cve_per_ric_repo[ric][repository] = [len(cves), cves]
            total = len(low_cves) + len(medium_cves) + len(high_cves) + len(critical_cves)
    
    print("Nonecounter: " + str(none_counter))
    
    return low_cvss_per_ric_repo, medium_cvss_per_ric_repo, high_cvss_per_ric_repo, critical_cvss_per_ric_repo, cve_per_ric_repo

# Analyze package distribution
def package_distribution_analysis(cvss_data):
    print("Analyzing package distribution...")

    packages_per_ric_repo = {ric: {} for ric in cvss_data.keys()}
    packages_per_ric = {ric: [] for ric in cvss_data.keys()}
    
    for ric in cvss_data.keys():
        ric_packages = []
        
        for repository in cvss_data[ric].keys():
            packages = []
            unique_packages = set()
            
            for sca_tool in cvss_data[ric][repository].keys():
                if cvss_data[ric][repository][sca_tool] is not None and sca_tool != "Scantist.json":
                    for path in cvss_data[ric][repository][sca_tool][2]:
                        packages.append(path)
                        ric_packages.append(path)
                        unique_packages.add(path)
            
            packages_per_ric_repo[ric][repository] = [{"unique_packages": len(unique_packages)}, dict(Counter(packages))]
        
        packages_per_ric[ric] = dict(Counter(ric_packages))
    
    print("Packages per RIC repo:", packages_per_ric_repo)
    print("Packages per RIC:", packages_per_ric)
    return packages_per_ric_repo, packages_per_ric

# Count total CVEs per RIC
def count_total_cves(low, medium, high, critical):
    total_cves = {ric: sum(len(low[ric][repo][1]) + len(medium[ric][repo][1]) + len(high[ric][repo][1]) + len(critical[ric][repo][1]) for repo in low[ric].keys()) for ric in low.keys()}
    return total_cves

# Tabulate CVSS scores per RIC
def tabulate_cvss(low_cve_data, medium_cve_data, high_cve_data, critical_cve_data):
    for ric in low_cve_data.keys():
        low_cve_count = 0
        medium_cve_count = 0
        high_cve_count = 0
        critical_cve_count = 0
        for repository in low_cve_data[ric]:
            if low_cve_data[ric][repository] is not None:
                low_cve_count += low_cve_data[ric][repository][0]
        for repository in medium_cve_data[ric]:
            if medium_cve_data[ric][repository] is not None:
                medium_cve_count += medium_cve_data[ric][repository][0]
        for repository in high_cve_data[ric]:
            if high_cve_data[ric][repository] is not None:
                high_cve_count += high_cve_data[ric][repository][0]
        for repository in critical_cve_data[ric]:
            if critical_cve_data[ric][repository] is not None:
                critical_cve_count += critical_cve_data[ric][repository][0]
        print("RIC: " + str(ric) + " TOTAL Low CVEs: " + str(low_cve_count))
        print("RIC: " + str(ric) + " TOTAL Medium CVEs: " + str(medium_cve_count))
        print("RIC: " + str(ric) + " TOTAL High CVEs: " + str(high_cve_count))
        print("RIC: " + str(ric) + " TOTAL Critical CVEs: " + str(critical_cve_count))


# Define a color-blind friendly palette
color_blind_friendly_palette = {
    'blue': '#0072B2',
    'orange': '#D55E00',
    'green': '#009E73',
    'yellow': '#F0E442',
    'red': '#CC79A7',
    'purple': '#CC79A7',
    'cyan': '#56B4E9',
    'grey': '#999999'
}
def generate_plots(total_vulnerabilities_ric, vulnerabilities_per_repo, severity_distribution, vulnerable_packages_per_ric, vulnerable_packages_per_repo):
    # Define a color-blind friendly palette
    color_blind_friendly_palette = {
        'blue': '#0072B2',
        'orange': '#D55E00',
        'green': '#009E73',
        'yellow': '#F0E442',
        'red': '#CC79A7',
        'purple': '#CC79A7',
        'cyan': '#56B4E9',
        'grey': '#999999'
    }

    # Plot total vulnerabilities per RIC
    plt.figure(figsize=(7, 5))  # Adjust the figure size to be more appropriate for a single bar
    plt.bar(total_vulnerabilities_ric.keys(), total_vulnerabilities_ric.values(), color=color_blind_friendly_palette['blue'], width=0.2)
    plt.title('Total Number of Vulnerabilities per RIC')
    plt.xlabel('RIC')
    plt.ylabel('Number of Vulnerabilities')
    plt.ylim(0, max(total_vulnerabilities_ric.values()) + 5)  # Adjust y-axis limit to fit the data
    plt.grid(axis='y')
    plt.tight_layout()  # Ensure everything fits without being cut off
    plt.savefig('total_vulnerabilities_per_ric.png', dpi=300)
    plt.show()

    # Plot vulnerabilities per repository
    for ric, repos in vulnerabilities_per_repo.items():
        plt.figure(figsize=(12, 6))
        plt.bar(repos.keys(), repos.values(), color=color_blind_friendly_palette['green'], width=0.5)
        plt.title(f'Vulnerabilities per Repository for {ric}')
        plt.xlabel('Repository')
        plt.ylabel('Number of Vulnerabilities')
        if repos.values():  # Check if the sequence is not empty
            plt.ylim(0, max(repos.values()) + 5)  # Adjust y-axis limit to fit the data
        else:
            plt.ylim(0, 5)  # Set a default y-axis limit
        plt.xticks(rotation=60)
        plt.grid(axis='y')
        plt.tight_layout()
        plt.savefig(f'vulnerabilities_per_repo_{ric}.png', dpi=300)
        plt.show()

    # Plot severity distribution
    for ric, severity in severity_distribution.items():
        plt.figure(figsize=(8, 4.5))
        colors = [color_blind_friendly_palette['green'], color_blind_friendly_palette['blue'], color_blind_friendly_palette['orange'], color_blind_friendly_palette['red']]
        plt.bar(severity.keys(), severity.values(), color=colors, width=0.5)
        plt.title(f'Severity Distribution for {ric}')
        plt.xlabel('Severity')
        plt.ylabel('Number of Vulnerabilities')
        plt.ylim(0, max(severity.values()) + 5)  # Adjust y-axis limit to fit the data
        plt.grid(axis='y')
        plt.savefig(f'severity_distribution_{ric}.png', dpi=300)
        plt.show()

    # Plot distribution of vulnerable packages per RIC
    plt.figure(figsize=(3, 5))
    plt.bar(vulnerable_packages_per_ric.keys(), vulnerable_packages_per_ric.values(), color=color_blind_friendly_palette['yellow'], width=0.5)
    plt.title('Distribution of Vulnerable Dependency Packages per RIC')
    plt.xlabel('RIC')
    plt.ylabel('Number of Vulnerable Packages')
    plt.ylim(0, max(vulnerable_packages_per_ric.values()) + 5)  # Adjust y-axis limit to fit the data
    plt.grid(axis='y')
    plt.savefig('vulnerable_packages_per_ric.png', dpi=300)
    plt.show()

    # Plot vulnerable packages per repository
    for ric, repos in vulnerable_packages_per_repo.items():
        plt.figure(figsize=(12, 6))
        plt.bar(repos.keys(), repos.values(), color=color_blind_friendly_palette['purple'], width=0.5)
        plt.title(f'Vulnerable Dependency Packages per Repository for {ric}')
        plt.xlabel('Repository')
        plt.ylabel('Number of Vulnerable Packages')
        if repos.values():  # Check if the sequence is not empty
            plt.ylim(0, max(repos.values()) + 5)  # Adjust y-axis limit to fit the data
        else:
            plt.ylim(0, 5)  # Set a default y-axis limit    
        plt.xticks(rotation=60)
        plt.grid(axis='y')
        plt.tight_layout()
        plt.savefig(f'vulnerable_packages_per_repo_{ric}.png', dpi=300)
        plt.show()

def main(data_files, tools, ric):
    for data_file, tool in zip(data_files, tools):
        # Load the data file
        with open(data_file, 'r') as file:
            data = file.read()

        # Get vulnerabilities by directory
        vulnerabilities_by_directory = get_vulnerabilities_by_directory(data, tool)

        # Save vulnerabilities by directory
        base_dir = f"./{ric}"
        save_vulnerabilities_by_directory(vulnerabilities_by_directory, tool, base_dir)

    # Dump scan results
    sca_results = dump_scan_results([ric], tools)
    sca_cvecvss_dependencies_results = extract_cves(sca_results)

    # Count CVEs
    count_cves(sca_cvecvss_dependencies_results)

    # Get per repo CVE count
    cve_per_ric_repo_tool, cve_per_ric_repo = per_repo_cve_count(sca_cvecvss_dependencies_results)

    # Get CVSS distribution
    low_cvss_per_ric_repo, medium_cvss_per_ric_repo, high_cvss_per_ric_repo, critical_cvss_per_ric_repo, cve_per_ric_repo = cvss_distribution(sca_cvecvss_dependencies_results)

    # Analyze package distribution
    packages_per_ric_repo, packages_per_ric = package_distribution_analysis(sca_cvecvss_dependencies_results)

    # Tabulate CVSS
    tabulate_cvss(low_cvss_per_ric_repo, medium_cvss_per_ric_repo, high_cvss_per_ric_repo, critical_cvss_per_ric_repo)

    # Calculate total vulnerabilities per RIC
    total_vulnerabilities_ric = count_total_cves(low_cvss_per_ric_repo, medium_cvss_per_ric_repo, high_cvss_per_ric_repo, critical_cvss_per_ric_repo)

    # Calculate vulnerabilities per repository
    vulnerabilities_per_repo = {ric: {repo: len(cves_without_dups) for repo, (_, cves_without_dups) in repos.items()} for ric, repos in cve_per_ric_repo.items()}

    # Calculate severity distribution
    severity_distribution = {
        ric: {
            'low': sum(len(low_cvss_per_ric_repo[ric][repo][1]) for repo in repos.keys()),
            'medium': sum(len(medium_cvss_per_ric_repo[ric][repo][1]) for repo in repos.keys()),
            'high': sum(len(high_cvss_per_ric_repo[ric][repo][1]) for repo in repos.keys()),
            'critical': sum(len(critical_cvss_per_ric_repo[ric][repo][1]) for repo in repos.keys())
        }
        for ric, repos in sca_cvecvss_dependencies_results.items()
    }

    # Calculate vulnerable packages per RIC
    vulnerable_packages_per_ric = {ric: len(packages) for ric, packages in packages_per_ric.items()}

    # Calculate vulnerable packages per repository
    vulnerable_packages_per_repo = {ric: {repo: packages_info[0]['unique_packages'] for repo, packages_info in repos.items()} for ric, repos in packages_per_ric_repo.items()}

    # Generate plots
    generate_plots(total_vulnerabilities_ric, vulnerabilities_per_repo, severity_distribution, vulnerable_packages_per_ric, vulnerable_packages_per_repo)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process SCA tool data")
    parser.add_argument('args', nargs='+', help='Arguments: data_files, tools, and ric')

    args = parser.parse_args()

    if len(args.args) < 7:
        raise ValueError("Expected at least 7 arguments: 3 data_files, 3 tools, and 1 ric name")

    data_files = args.args[:3]
    tools = args.args[3:6]
    ric = args.args[6]

    main(data_files, tools, ric)