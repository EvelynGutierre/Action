import os
import json
import shutil

def extract_cve_info(cve_data):
    cve_id = cve_data.get('cveMetadata', {}).get('cveId', 'N/A')
    products = cve_data.get('containers', {}).get('cna', {}).get('affected', [])
    
    product_info = []
    for product in products:
        product_name = product.get('product', 'N/A')
        vendor = product.get('vendor', 'N/A')
        product_info.append({
            "Product": product_name,
            "Vendor": vendor
        })

    return {
        "CVE ID": cve_id,
        "Products": product_info
    }

def match_cve_to_pypi(cve_info_list, pypi_file_path):
    try:
        with open(pypi_file_path, 'r') as pypi_file:
            pypi_data = json.load(pypi_file)
    except FileNotFoundError:
        print(f"Error: File '{pypi_file_path}' not found.")
        return cve_info_list
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from file '{pypi_file_path}': {str(e)}")
        return cve_info_list

    for cve_info in cve_info_list:
        for product_info in cve_info['Products']:
            product_name = product_info['Product']
            vendor = product_info['Vendor']

            # Check if product_name and vendor match any entries in pypi_data
            matched_packages = []
            for package in pypi_data:
                if isinstance(package, dict):  # Check if package is a dictionary
                    if package.get('name') == product_name and package.get('author') == vendor:
                        matched_packages.append(package)

            # Add matched packages to cve_info
            product_info['Matched Packages'] = matched_packages

    return cve_info_list

def check_cves_in_folder(folder_path, pypi_file_path, output_folder):
    cve_files = [f for f in os.listdir(folder_path) if f.endswith('.json')]
    cve_info_list = []

    for cve_file in cve_files:
        file_path = os.path.join(folder_path, cve_file)
        with open(file_path, 'r') as file:
            try:
                cve_data = json.load(file)
                cve_info = extract_cve_info(cve_data)
                cve_info_list.append(cve_info)
            except json.JSONDecodeError:
                print(f"Error decoding JSON from file: {file_path}")

    # Match CVE information to packages in pypi_packages.json
    cve_info_list_with_matches = match_cve_to_pypi(cve_info_list, pypi_file_path)

    # Create the output folder if it doesn't exist
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    matched_cve_info_list = []
    for cve_info, cve_file in zip(cve_info_list_with_matches, cve_files):
        has_matched_packages = any(product_info['Matched Packages'] for product_info in cve_info['Products'])
        if has_matched_packages:
            matched_cve_info_list.append(cve_info)
            # Copy the original CVE file to the new folder
            shutil.copy(file_path, os.path.join(output_folder, cve_file))

    return matched_cve_info_list

def save_cve_info_to_json(cve_info_list, output_folder):
    # Sort CVE info list by CVE ID
    sorted_cve_info_list = sorted(cve_info_list, key=lambda x: x['CVE ID'])

    output_file = os.path.join(output_folder, "cve_info_updated.json")
    with open(output_file, 'w') as file:
        json.dump(sorted_cve_info_list, file, indent=4)

    print(f"CVE information saved to: {output_file}")

def process_all_folders(base_folder_path, pypi_file_path):
    folder_names = os.listdir(base_folder_path)
    sorted_folder_names = sorted(folder_names)
    
    for folder_name in sorted_folder_names:
        folder_path = os.path.join(base_folder_path, folder_name)
        if os.path.isdir(folder_path):
            output_folder = os.path.join('CVEwInfo/2022', folder_name)
            matched_cve_info_list = check_cves_in_folder(folder_path, pypi_file_path, output_folder)
            save_cve_info_to_json(matched_cve_info_list, output_folder)

# Specify the base folder path containing the subfolders with CVE JSON files
base_folder_path = 'cvelistV5/cves/2022'

# Specify the path to pypi_packages.json
pypi_file_path = 'pypi_packages.json'

# Process all subfolders in the base folder
process_all_folders(base_folder_path, pypi_file_path)
