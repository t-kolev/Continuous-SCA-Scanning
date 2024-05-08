# Continuous SCA Scanning

## Overview

Welcome to the repository for the workflows used in my thesis on Continuous SCA (Software Composition Analysis) Scanning. This project aims to provide a comprehensive framework for continuously scanning open-sourced codebases for security vulnerabilities.

## Contents

This repository contains the following:

1. **Workflow Files**:
    - YAML files for running scans with 3 different tools:
      - Grype
      - Trivy
      - Snyk

## Usage

The workflows provided here are reusable, facilitating the easy introduction and testing of various scanning tools.

To use the workflows in this repository, follow these steps:

1. Create a folder named `.github/workflows` in the repository you want to scan.
2. Create new workflows depending on the tools you want to use.
3. At the beginning of the `jobs` key, add the following option:
   ```
   uses: t-kolev/Continuous-SCA-Scanning/.github/workflows/snyk.yaml@main
   ```

## Acknowledgments

Special thanks to Dr. Kashyap Thimmaraju for his guidance and support throughout this thesis project.
