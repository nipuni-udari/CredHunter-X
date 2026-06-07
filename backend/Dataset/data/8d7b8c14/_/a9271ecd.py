# Disease Q&A with Perplexity AI API - Interactive Browser App
# ========================================================

# This notebook demonstrates how to build a disease Q&A system using Perplexity's AI API
# and generates an HTML file that can be opened in a browser with an interactive UI

# 1. Setup and Dependencies
# ------------------------

import requests
import json
import pandas as pd
from IPython.display import HTML, display, IFrame
import os
import webbrowser
from pathlib import Path

# 2. API Configuration
# -------------------

# Replace with your actual Perplexity API key
API_KEY = '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'  # This is from your HTML file
API_ENDPOINT = 'https://api.perplexity.ai/chat/completions'

# 3. Function to Query Perplexity API (for testing in notebook)
# ----------------------------------

def ask_disease_question(question):
    """
    Send a disease-related question to Perplexity API and parse the response.
    
    Args:
        question (str): The question about a disease
        
    Returns:
        dict: JSON response with overview, causes, treatments, and citations
    """
    # Construct a prompt instructing the API to output only valid JSON
    prompt = f"""
You are a medical assistant. Please answer the following question about a disease and provide only valid JSON output.
The JSON object must have exactly four keys: "overview", "causes", "treatments", and "citations".
For example:
{{
  "overview": "A brief description of the disease.",
  "causes": "The causes of the disease.",
  "treatments": "Possible treatments for the disease.",
  "citations": ["https://example.com/citation1", "https://example.com/citation2"]
}}
Now answer this question:
"{question}"
    """.strip()

    # Build the payload
    payload = {
        "model": "sonar-pro",
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }

    try:
        # Make the API request
        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(API_ENDPOINT, headers=headers, json=payload)
        response.raise_for_status()  # Raise exception for 4XX/5XX responses
        
        result = response.json()
        
        # Extract and parse the response
        if result.get("choices") and len(result["choices"]) > 0:
            content = result["choices"][0]["message"]["content"]
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                print("Failed to parse JSON output from API. Raw output:")
                print(content)
                return None
        else:
            print("No answer provided in the response.")
            return None
            
    except Exception as e:
        print(f"Error: {e}")
        return None

# 4. Create HTML UI File
# ----------------------

def create_html_ui(api_key, output_path="disease_qa.html"):
    """
    Create an HTML file with the disease Q&A interface
    
    Args:
        api_key (str): The Perplexity API key
        output_path (str): The path where the HTML file should be saved
    
    Returns:
        str: The path to the created HTML file
    """
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Disease Q&A Knowledge Card</title>
  <style>
    /* Base styling */
    body {{
      font-family: Helvetica, Arial, sans-serif;
      background-color: #F7F7F8; /* Light background */
      color: #333;
      margin: 0;
      padding: 0;
    }}
    .container {{
      max-width: 800px;
      margin: 2rem auto;
      padding: 1rem;
    }}
    h1 {{
      text-align: center;
      color: #111;
      margin-bottom: 1rem;
    }}
    /* Form styling */
    #qaForm {{
      display: flex;
      justify-content: center;
      margin-bottom: 1.5rem;
    }}
    #question {{
      flex: 1;
      padding: 0.75rem;
      font-size: 1.2rem;
      border: 1px solid #ccc;
      border-radius: 4px;
      margin-right: 0.5rem;
    }}
    #askButton {{
      padding: 0.75rem 1rem;
      font-size: 1.2rem;
      background-color: #10a37f; /* Accent color */
      border: none;
      color: #fff;
      border-radius: 4px;
      cursor: pointer;
      transition: background-color 0.2s ease;
    }}
    #askButton:hover {{
      background-color: #0d8a66;
    }}
    /* Knowledge card and citations styling */
    #knowledgeCard, #citationsCard {{
      background: #fff;
      border: 1px solid #e0e0e0;
      border-radius: 8px;
      padding: 1rem;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      margin-top: 1.5rem;
      display: none;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    th, td {{
      text-align: left;
      padding: 0.75rem;
      border-bottom: 1px solid #e0e0e0;
    }}
    th {{
      background-color: #fafafa;
      width: 25%;
    }}
    /* Citations list styling */
    #citationsList {{
      list-style-type: disc;
      padding-left: 20px;
    }}
    #citationsList li {{
      margin-bottom: 0.5rem;
    }}
    #citationsList a {{
      color: #10a37f;
      text-decoration: none;
    }}
    #citationsList a:hover {{
      text-decoration: underline;
    }}
    /* Loading overlay styling */
    #loadingOverlay {{
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(255, 255, 255, 0.8);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 9999;
      display: none;
    }}
    .spinner {{
      border: 8px solid #f3f3f3;
      border-top: 8px solid #10a37f;
      border-radius: 50%;
      width: 60px;
      height: 60px;
      animation: spin 1s linear infinite;
    }}
    @keyframes spin {{
      0% {{ transform: rotate(0deg); }}
      100% {{ transform: rotate(360deg); }}
    }}
    /* Added footer with tutorial info */
    .footer {{
      text-align: center;
      margin-top: 2rem;
      padding: 1rem;
      font-size: 0.9rem;
      color: #777;
    }}
  </style>
</head>
<body>
  <!-- Loading Overlay -->
  <div id="loadingOverlay">
    <div class="spinner"></div>
  </div>

  <div class="container">
    <h1>Disease Q&A</h1>
    <form id="qaForm">
      <input type="text" id="question" placeholder="Ask a question about a disease (e.g., 'What is stroke?')" required>
      <button type="submit" id="askButton">Ask</button>
    </form>

    <!-- Knowledge card container -->
    <div id="knowledgeCard">
      <h2>Knowledge Card</h2>
      <table>
        <tr>
          <th>Overview</th>
          <td id="overview"></td>
        </tr>
        <tr>
          <th>Causes</th>
          <td id="causes"></td>
        </tr>
        <tr>
          <th>Treatments</th>
          <td id="treatments"></td>
        </tr>
      </table>
    </div>

    <!-- Citations container -->
    <div id="citationsCard">
      <h2>Citations</h2>
      <ul id="citationsList"></ul>
    </div>
    
    <div class="footer">
      <p>Created with Sonar API</p>
    </div>
  </div>

  <script>
    // API key from Python notebook
    const API_KEY = '{api_key}';
    // API endpoint as per Perplexity's documentation
    const API_ENDPOINT = 'https://api.perplexity.ai/chat/completions';

    async function askDiseaseQuestion(question) {{
      // Construct a prompt instructing the API to output only valid JSON
      const prompt = `
You are a medical assistant. Please answer the following question about a disease and provide only valid JSON output.
The JSON object must have exactly four keys: "overview", "causes", "treatments", and "citations".
For example:
{{
  "overview": "A brief description of the disease.",
  "causes": "The causes of the disease.",
  "treatments": "Possible treatments for the disease.",
  "citations": ["https://example.com/citation1", "https://example.com/citation2"]
}}
Now answer this question:
"${{question}}"
      `.trim();

      // Build the payload
      const payload = {{
        model: 'sonar-pro',
        messages: [
          {{ role: 'user', content: prompt }}
        ]
      }};

      try {{
        const response = await fetch(API_ENDPOINT, {{
          method: 'POST',
          headers: {{
            'Authorization': `Bearer ${{API_KEY}}`,
            'Content-Type': 'application/json'
          }},
          body: JSON.stringify(payload)
        }});

        if (!response.ok) {{
          throw new Error(`Error: ${{response.status}} - ${{response.statusText}}`);
        }}

        const result = await response.json();

        // The answer is expected in the first choice's message content
        if (result.choices && result.choices.length > 0) {{
          const content = result.choices[0].message.content;
          try {{
            const structuredOutput = JSON.parse(content);
            return structuredOutput;
          }} catch (jsonErr) {{
            throw new Error('Failed to parse JSON output from API. Raw output: ' + content);
          }}
        }} else {{
          throw new Error('No answer provided in the response.');
        }}
      }} catch (error) {{
        console.error(error);
        alert(error);
      }}
    }}

    // Utility to show/hide the loading overlay
    function setLoading(isLoading) {{
      document.getElementById('loadingOverlay').style.display = isLoading ? 'flex' : 'none';
    }}

    // Handle form submission
    document.getElementById('qaForm').addEventListener('submit', async (event) => {{
      event.preventDefault();

      // Hide previous results
      document.getElementById('knowledgeCard').style.display = 'none';
      document.getElementById('citationsCard').style.display = 'none';

      // Show loading overlay
      setLoading(true);

      const question = document.getElementById('question').value;
      const data = await askDiseaseQuestion(question);

      // Hide loading overlay once done
      setLoading(false);

      if (data) {{
        // Update the knowledge card with structured data
        document.getElementById('overview').textContent = data.overview || 'N/A';
        document.getElementById('causes').textContent = data.causes || 'N/A';
        document.getElementById('treatments').textContent = data.treatments || 'N/A';
        document.getElementById('knowledgeCard').style.display = 'block';

        // Update the citations section
        const citationsList = document.getElementById('citationsList');
        citationsList.innerHTML = ''; // Clear previous citations
        if (Array.isArray(data.citations) && data.citations.length > 0) {{
          data.citations.forEach(citation => {{
            const li = document.createElement('li');
            const link = document.createElement('a');
            link.href = citation;
            link.textContent = citation;
            link.target = '_blank';
            li.appendChild(link);
            citationsList.appendChild(li);
          }});
        }} else {{
          const li = document.createElement('li');
          li.textContent = 'No citations provided.';
          citationsList.appendChild(li);
        }}
        document.getElementById('citationsCard').style.display = 'block';
      }}
    }});
  </script>
</body>
</html>
"""

    # Write the HTML to a file
    with open(output_path, 'w') as f:
        f.write(html_content)
    
    # Get the full path
    full_path = os.path.abspath(output_path)
    return full_path

# 5. Function to Display Results in Notebook (for testing)
# -----------------------------

def display_results(data):
    """
    Display the results in a structured format within the notebook.
    
    Args:
        data (dict): The parsed JSON data from the API
    """
    if not data:
        print("No data to display.")
        return
    
    # Create a DataFrame for the main knowledge card
    df = pd.DataFrame({
        "Category": ["Overview", "Causes", "Treatments"],
        "Information": [
            data.get("overview", "N/A"),
            data.get("causes", "N/A"),
            data.get("treatments", "N/A")
        ]
    })
    
    # Display the knowledge card
    print("\n💡 Knowledge Card:")
    display(df.style.set_table_styles([
        {'selector': 'th', 'props': [('background-color', '#fafafa'), ('color', '#333'), ('font-weight', 'bold')]},
        {'selector': 'td', 'props': [('padding', '10px')]},
    ]))
    
    # Display citations
    print("\n📚 Citations:")
    if data.get("citations") and isinstance(data["citations"], list) and len(data["citations"]) > 0:
        for i, citation in enumerate(data["citations"], 1):
            print(f"{i}. {citation}")
    else:
        print("No citations provided.")

# 6. Function to Launch Browser UI
# -------------------------------

def launch_browser_ui(api_key=API_KEY, html_path="disease_qa.html"):
    """
    Generate and open the HTML UI in a web browser.
    
    Args:
        api_key (str): The Perplexity API key
        html_path (str): Path to save the HTML file
        
    Returns:
        str: The path to the created HTML file
    """
    # Create the HTML file
    full_path = create_html_ui(api_key, html_path)
    
    # Convert to file:// URL format
    file_url = f"file://{full_path}"
    
    # Open in the default web browser
    print(f"Opening browser UI: {file_url}")
    webbrowser.open(file_url)
    
    return full_path

# 7. Example Usage
# ---------------

# Example 1: Testing the API in the notebook
def test_api_in_notebook():
    print("Example 1: Direct API Call")
    print("-------------------------")
    example_question = "What is diabetes?"
    print(f"Question: {example_question}")
    print("Sending request to Perplexity API...")

    # Uncomment the following lines to make a real API call
    # result = ask_disease_question(example_question)
    # display_results(result)

    print("(API call commented out to avoid using your API quota)")
    print("\n")

# Example 2: Generate HTML file and open in browser
def launch_browser_app():
    print("Example 2: Launching Browser UI")
    print("-----------------------------")
    print("Generating HTML file and opening in browser...")
    
    # Create and open the HTML file
    path = launch_browser_ui()
    
    print(f"\nHTML file created at: {path}")
    print("\nIf the browser doesn't open automatically, you can manually open the file above.")
    
    # Show a preview in the notebook (not all notebook environments support this)
    try:
        display(HTML(f'<p>Preview of UI (may not work in all environments):</p>'))
        display(IFrame(path, width='100%', height=600))
    except:
        print("Preview not available in this environment.")

# Run the examples
test_api_in_notebook()
launch_browser_app()

# 8. Tutorial Explanation
# ---------------------

"""
How this tutorial works:

1. We've created a Python function that generates an HTML file containing the Disease Q&A interface
2. The HTML file includes all the necessary CSS styling and JavaScript for the UI
3. The JavaScript code makes requests to the Perplexity API when the user submits a question
4. We use Python's webbrowser module to automatically open the generated HTML file in a browser
5. The application runs entirely in the browser, with API requests made directly from JavaScript

Benefits of this approach:
- Creates a standalone HTML file that can be shared and used independently
- Provides a clean, professional UI similar to the original HTML
- No need for a server to run the application
- API requests are made directly from the browser, reducing complexity

Customization Options:
- You can modify the HTML template to change the appearance
- You can update the API prompt format to get different structured data
- You can add additional fields to the knowledge card

Security Notes:
- The API key is embedded in the HTML file, which isn't secure for production use
- For a production app, you should use a backend server to handle API requests
- This tutorial is for educational purposes only
"""

# 9. Additional Concepts and Extensions
# -----------------------------------

"""
Extensions you could implement:
1. Add a backend server with Flask to handle API requests (keeping your API key secure)
2. Implement caching to avoid repeated calls for the same questions
3. Add a history feature to see previous questions and answers
4. Create a more sophisticated prompt to get better structured data
5. Add visualization for disease statistics if available
6. Implement a feedback mechanism for answers
7. Add a feature to compare multiple diseases

Production Deployment Options:
1. Deploy as a simple static site with a serverless backend (like AWS Lambda)
2. Create a full Flask/Django app with proper API key management
3. Build a desktop application with Electron
4. Convert to a mobile app with React Native or Flutter
"""

# 10. Conclusion
# ------------

"""
This notebook demonstrates how to create a browser-based disease Q&A system using Perplexity's AI API.
The system provides a user-friendly interface for querying information about various diseases.

Key takeaways:
1. You can create interactive web applications directly from Python
2. The Perplexity API can be used to create structured responses for specific domains
3. A properly formatted prompt is key to getting consistent structured data
4. Combining Python (for generation) and JavaScript (for runtime) gives you flexibility

Remember to replace the API key with your own before sharing this application!
"""