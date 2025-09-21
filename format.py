import os
from pdfminer.high_level import extract_text
from pathlib import Path

def convert_pdf_to_html(pdf_path, output_dir="data"):
    """
    Convert PDF to HTML using pdfminer.six
    """
    try:
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        filename = os.path.splitext(os.path.basename(pdf_path))[0]
        output_path = os.path.join(output_dir, f"{filename}.html")
        
        # Extract text from PDF
        text = extract_text(pdf_path)
        
        # Create basic HTML structure
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{filename}</title>
    <style>
        body {{ 
            font-family: Arial, sans-serif; 
            margin: 40px; 
            line-height: 1.6;
            max-width: 1200px;
        }}
        .content {{ white-space: pre-wrap; }}
        .header {{ 
            background-color: #f0f0f0; 
            padding: 20px; 
            margin-bottom: 30px;
            border-radius: 5px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{filename}</h1>
        <p>Converted from PDF to HTML</p>
    </div>
    <div class="content">
        {text}
    </div>
</body>
</html>"""
        
        with open(output_path, 'w', encoding='utf-8') as html_file:
            html_file.write(html_content)
        
        print(f"✓ Successfully converted: {pdf_path}")
        return True
        
    except Exception as e:
        print(f"✗ Error converting {pdf_path}: {str(e)}")
        return False

def main():
    # Check if pdfminer.six is available
    try:
        from pdfminer.high_level import extract_text
    except ImportError:
        print("Installing required packages...")
        os.system("pip install pdfminer.six")
        from pdfminer.high_level import extract_text
    
    # Specify the input directory
    input_dir = "reports"
    
    # Check if input directory exists
    if not os.path.exists(input_dir):
        print(f"Error: Directory '{input_dir}' not found.")
        print("Please make sure you're running the script from the directory containing the 'reports' folder.")
        return
    
    pdf_files = []
    
    # Find all PDF files in the input directory
    for file in os.listdir(input_dir):
        if file.lower().endswith('.pdf'):
            pdf_files.append(os.path.join(input_dir, file))
    
    if not pdf_files:
        print(f"No PDF files found in the '{input_dir}' directory.")
        return
    
    print(f"Found {len(pdf_files)} PDF file(s) in '{input_dir}':")
    for pdf in pdf_files:
        print(f"  - {os.path.basename(pdf)}")
    
    print("\nStarting conversion...")
    
    success_count = 0
    for pdf_file in pdf_files:
        if convert_pdf_to_html(pdf_file, "data"):
            success_count += 1
    
    print(f"\nConversion complete: {success_count}/{len(pdf_files)} files converted successfully")
    
    # Show the created HTML files
    if success_count > 0:
        print("\nGenerated HTML files in 'data' directory:")
        html_files = [f for f in os.listdir("data") if f.endswith('.html')]
        for html_file in html_files:
            file_path = os.path.join("data", html_file)
            file_size = os.path.getsize(file_path)
            print(f"  - {html_file} ({file_size} bytes)")

if __name__ == "__main__":
    main()