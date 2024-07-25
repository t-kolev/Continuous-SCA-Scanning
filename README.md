# Continuous SCA Scanning

## Overview

Welcome to the repository for the workflows used in my thesis on Continuous SCA (Software Composition Analysis) Scanning. This project aims to provide a comprehensive framework for continuously scanning open-source codebases for security vulnerabilities. We focused on evaluating the security of one of the crucial O-RAN components - Near-Real-Time RIC.


## Contents

This repository contains the following:

1. **Workflow Files** (in the `.github/workflows` directory):
    - YAML files for running scans with three different SCA tools:
        - Grype
        - Trivy
        - Snyk
2. **Links**:
    - Text files containing links to the GitHub repositories for the three RICs where we established continuous scanning:
        - `oaic_links.txt`
        - `onos_links.txt`
        - `osc_links.txt`
3. **Data Analysis**:
    - Script used for data analysis.
4. **Scripts**:
    - Script for updating the repository.
5. **Continuous SCA Tool YAML File**:
    - YAML file that builds the proposed solution.

### Detailed Setup

1. **Prepare Repository Links**:
    - Create a text file that includes links to the GitHub repositories of all the components that build the specific Near-RT RIC.

2. **Set Up Scanning Repository**:
    - Create a repository where the scanning will be performed.
    - Include the following files from our GitHub repository:
        - Repository creation/update script
        - YAML file named `continuous_sca_scanning.yaml`
        - Data analysis script with the Python requirements file

3. **Configure Workflow Directory**:
    - Ensure the `continuous_sca_scanning.yaml` file is in the `.github/workflows` directory so GitHub recognizes it as a workflow.

4. **Add Necessary Secrets**:
    - Add the Git username and email as secrets for new commits when a repository needs to be updated.
    - For using the Snyk SCA tool, create a free Snyk profile and add the personal token as a secret in the Snyk YAML file.

## Usage of the SCA Tools

The workflows for the SCA scanning tools provided here are reusable, facilitating the easy introduction and testing of various scanning tools.

To use the workflows in a repository, follow these steps:

1. Create a folder named `.github/workflows` in the repository you want to scan.
2. Create new workflows depending on the tools you want to use.
3. At the beginning of the `jobs` key, add the following option according to the tool you want to use:

   For example, if you want to use the Trivy SCA workflow, you import it like this:

   ```yaml
   uses: t-kolev/Continuous-SCA-Scanning/.github/workflows/trivy.yaml@main

## Acknowledgments

Special thanks to Dr. Kashyap Thimmaraju for his guidance and support throughout this thesis project.

For any issues or questions, please feel free to raise an issue in this repository.
