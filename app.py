# AI Code Review Assistant
# Complete Flask application for automated code reviews

import os
import json
import requests
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import difflib
import ast
import subprocess
import tempfile
import openai
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
CORS(app)

# Configuration
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', 'your-openai-api-key')
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', 'your-github-token')
DATABASE_PATH = 'code_reviews.db'

# Initialize OpenAI
openai.api_key = OPENAI_API_KEY

@dataclass
class CodeIssue:
    """Represents a code review issue"""
    line_number: int
    severity: str  # 'error', 'warning', 'suggestion'
    category: str  # 'security', 'performance', 'style', 'logic', 'maintainability'
    message: str
    suggestion: str
    file_path: str

@dataclass
class ReviewResult:
    """Represents a complete code review result"""
    issues: List[CodeIssue]
    overall_score: int  # 0-100
    summary: str
    total_lines_reviewed: int
    timestamp: datetime

class DatabaseManager:
    """Handles database operations"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Reviews table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pr_url TEXT NOT NULL,
                repository TEXT NOT NULL,
                branch TEXT NOT NULL,
                overall_score INTEGER,
                summary TEXT,
                total_lines INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Issues table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                review_id INTEGER,
                file_path TEXT,
                line_number INTEGER,
                severity TEXT,
                category TEXT,
                message TEXT,
                suggestion TEXT,
                FOREIGN KEY (review_id) REFERENCES reviews (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_review(self, pr_url: str, repository: str, branch: str, result: ReviewResult) -> int:
        """Save a review result to the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Insert review
        cursor.execute('''
            INSERT INTO reviews (pr_url, repository, branch, overall_score, summary, total_lines)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (pr_url, repository, branch, result.overall_score, result.summary, result.total_lines_reviewed))
        
        review_id = cursor.lastrowid
        
        # Insert issues
        for issue in result.issues:
            cursor.execute('''
                INSERT INTO issues (review_id, file_path, line_number, severity, category, message, suggestion)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (review_id, issue.file_path, issue.line_number, issue.severity, 
                  issue.category, issue.message, issue.suggestion))
        
        conn.commit()
        conn.close()
        return review_id
    
    def get_review_history(self, limit: int = 10) -> List[Dict]:
        """Get recent review history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM reviews 
            ORDER BY created_at DESC 
            LIMIT ?
        ''', (limit,))
        
        reviews = cursor.fetchall()
        conn.close()
        
        return [dict(zip([col[0] for col in cursor.description], row)) for row in reviews]

class CodeAnalyzer:
    """Analyzes code for various issues"""
    
    def __init__(self):
        self.patterns = {
            'security': [
                (r'eval\s*\(', 'Dangerous use of eval() function'),
                (r'exec\s*\(', 'Dangerous use of exec() function'),
                (r'import\s+os\s*;.*os\.system', 'Potential command injection'),
                (r'subprocess\.call\s*\(.*shell\s*=\s*True', 'Shell injection vulnerability'),
                (r'pickle\.loads?\s*\(', 'Unsafe deserialization with pickle'),
            ],
            'performance': [
                (r'for\s+\w+\s+in\s+range\s*\(\s*len\s*\(', 'Consider using enumerate() instead'),
                (r'\+\s*=.*\[.*\]', 'Consider using list.extend() for better performance'),
                (r'\.keys\s*\(\s*\)\s*:', 'Unnecessary .keys() call in iteration'),
            ],
            'style': [
                (r'^\s*#.*TODO', 'TODO comment found'),
                (r'^\s*#.*FIXME', 'FIXME comment found'),
                (r'print\s*\(', 'Consider using logging instead of print'),
                (r'lambda.*:', 'Consider using a named function instead of lambda'),
            ]
        }
    
    def analyze_python_code(self, code: str, file_path: str) -> List[CodeIssue]:
        """Analyze Python code for issues"""
        issues = []
        lines = code.split('\n')
        
        # Pattern-based analysis
        for line_num, line in enumerate(lines, 1):
            for category, patterns in self.patterns.items():
                for pattern, message in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        severity = 'error' if category == 'security' else 'warning'
                        issues.append(CodeIssue(
                            line_number=line_num,
                            severity=severity,
                            category=category,
                            message=message,
                            suggestion=self._get_suggestion(pattern, line),
                            file_path=file_path
                        ))
        
        # AST-based analysis
        try:
            tree = ast.parse(code)
            ast_issues = self._analyze_ast(tree, file_path)
            issues.extend(ast_issues)
        except SyntaxError as e:
            issues.append(CodeIssue(
                line_number=e.lineno or 1,
                severity='error',
                category='syntax',
                message=f'Syntax error: {e.msg}',
                suggestion='Fix the syntax error',
                file_path=file_path
            ))
        
        return issues
    
    def _analyze_ast(self, tree: ast.AST, file_path: str) -> List[CodeIssue]:
        """Analyze AST for code issues"""
        issues = []
        
        class CodeVisitor(ast.NodeVisitor):
            def visit_FunctionDef(self, node):
                # Check for functions without docstrings
                if not ast.get_docstring(node) and not node.name.startswith('_'):
                    issues.append(CodeIssue(
                        line_number=node.lineno,
                        severity='suggestion',
                        category='documentation',
                        message=f'Function "{node.name}" lacks documentation',
                        suggestion='Add a docstring to explain the function purpose',
                        file_path=file_path
                    ))
                
                # Check for too many arguments
                if len(node.args.args) > 5:
                    issues.append(CodeIssue(
                        line_number=node.lineno,
                        severity='warning',
                        category='maintainability',
                        message=f'Function "{node.name}" has too many parameters ({len(node.args.args)})',
                        suggestion='Consider reducing parameters or using a configuration object',
                        file_path=file_path
                    ))
                
                self.generic_visit(node)
            
            def visit_ClassDef(self, node):
                # Check for classes without docstrings
                if not ast.get_docstring(node):
                    issues.append(CodeIssue(
                        line_number=node.lineno,
                        severity='suggestion',
                        category='documentation',
                        message=f'Class "{node.name}" lacks documentation',
                        suggestion='Add a docstring to explain the class purpose',
                        file_path=file_path
                    ))
                
                self.generic_visit(node)
        
        visitor = CodeVisitor()
        visitor.visit(tree)
        return issues
    
    def _get_suggestion(self, pattern: str, line: str) -> str:
        """Get improvement suggestion based on the pattern"""
        suggestions = {
            r'eval\s*\(': 'Use ast.literal_eval() for safe evaluation of literals',
            r'exec\s*\(': 'Avoid exec() or use safer alternatives',
            r'for\s+\w+\s+in\s+range\s*\(\s*len\s*\(': 'Use: for i, item in enumerate(items):',
            r'print\s*\(': 'Use logging.info() or logger.debug() instead',
            r'\+\s*=.*\[.*\]': 'Use list.extend() for better performance',
        }
        
        for pat, suggestion in suggestions.items():
            if re.search(pat, pattern):
                return suggestion
        
        return 'Consider refactoring this code'

class AIReviewer:
    """Uses AI to provide intelligent code review"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        openai.api_key = api_key
    
    def review_code_with_ai(self, code: str, file_path: str, context: str = "") -> List[CodeIssue]:
        """Use OpenAI to review code and suggest improvements"""
        if not self.api_key or self.api_key == 'your-openai-api-key':
            return []  # Skip AI review if no API key
        
        try:
            prompt = f"""
            Please review the following code and provide specific feedback:
            
            File: {file_path}
            Context: {context}
            
            Code:
            ```
            {code}
            ```
            
            Please analyze for:
            1. Security vulnerabilities
            2. Performance issues
            3. Code style and best practices
            4. Logic errors
            5. Maintainability concerns
            
            Return your analysis in JSON format with the following structure:
            {{
                "issues": [
                    {{
                        "line_number": 1,
                        "severity": "error|warning|suggestion",
                        "category": "security|performance|style|logic|maintainability",
                        "message": "Description of the issue",
                        "suggestion": "Specific improvement suggestion"
                    }}
                ]
            }}
            """
            
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are an expert code reviewer. Provide detailed, actionable feedback."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1500,
                temperature=0.1
            )
            
            content = response.choices[0].message.content
            
            # Try to parse JSON response
            try:
                ai_result = json.loads(content)
                issues = []
                
                for issue_data in ai_result.get('issues', []):
                    issues.append(CodeIssue(
                        line_number=issue_data.get('line_number', 1),
                        severity=issue_data.get('severity', 'suggestion'),
                        category=issue_data.get('category', 'general'),
                        message=issue_data.get('message', ''),
                        suggestion=issue_data.get('suggestion', ''),
                        file_path=file_path
                    ))
                
                return issues
            
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse AI response as JSON: {content}")
                return []
        
        except Exception as e:
            logger.error(f"AI review failed: {e}")
            return []

class GitHubIntegration:
    """Handles GitHub API integration"""
    
    def __init__(self, token: str):
        self.token = token
        self.headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
    
    def get_pr_files(self, repo_url: str, pr_number: int) -> List[Dict]:
        """Get files changed in a pull request"""
        try:
            # Extract owner and repo from URL
            parts = repo_url.replace('https://github.com/', '').split('/')
            owner, repo = parts[0], parts[1]
            
            url = f'https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files'
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            return response.json()
        
        except Exception as e:
            logger.error(f"Failed to fetch PR files: {e}")
            return []
    
    def get_file_content(self, repo_url: str, file_path: str, ref: str = 'main') -> str:
        """Get content of a specific file"""
        try:
            parts = repo_url.replace('https://github.com/', '').split('/')
            owner, repo = parts[0], parts[1]
            
            url = f'https://api.github.com/repos/{owner}/{repo}/contents/{file_path}'
            params = {'ref': ref}
            
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            
            import base64
            content = response.json()['content']
            return base64.b64decode(content).decode('utf-8')
        
        except Exception as e:
            logger.error(f"Failed to fetch file content: {e}")
            return ""

class CodeReviewService:
    """Main service that orchestrates the code review process"""
    
    def __init__(self):
        self.db = DatabaseManager(DATABASE_PATH)
        self.analyzer = CodeAnalyzer()
        self.ai_reviewer = AIReviewer(OPENAI_API_KEY)
        self.github = GitHubIntegration(GITHUB_TOKEN)
    
    def review_pull_request(self, repo_url: str, pr_number: int) -> ReviewResult:
        """Review a complete pull request"""
        logger.info(f"Starting review for PR #{pr_number} in {repo_url}")
        
        # Get PR files
        pr_files = self.github.get_pr_files(repo_url, pr_number)
        
        all_issues = []
        total_lines = 0
        
        for file_info in pr_files:
            file_path = file_info['filename']
            
            # Only analyze Python files for now
            if not file_path.endswith('.py'):
                continue
            
            # Get file content
            content = self.github.get_file_content(repo_url, file_path)
            if not content:
                continue
            
            total_lines += len(content.split('\n'))
            
            # Analyze with static analyzer
            static_issues = self.analyzer.analyze_python_code(content, file_path)
            all_issues.extend(static_issues)
            
            # Analyze with AI
            ai_issues = self.ai_reviewer.review_code_with_ai(
                content, file_path, f"PR #{pr_number} review"
            )
            all_issues.extend(ai_issues)
        
        # Calculate overall score
        score = self._calculate_score(all_issues, total_lines)
        
        # Generate summary
        summary = self._generate_summary(all_issues, total_lines)
        
        result = ReviewResult(
            issues=all_issues,
            overall_score=score,
            summary=summary,
            total_lines_reviewed=total_lines,
            timestamp=datetime.now()
        )
        
        # Save to database
        self.db.save_review(repo_url, repo_url.split('/')[-1], f"pr-{pr_number}", result)
        
        return result
    
    def review_code_snippet(self, code: str, file_path: str = "snippet.py") -> ReviewResult:
        """Review a code snippet"""
        logger.info(f"Reviewing code snippet: {file_path}")
        
        # Analyze with static analyzer
        static_issues = self.analyzer.analyze_python_code(code, file_path)
        
        # Analyze with AI
        ai_issues = self.ai_reviewer.review_code_with_ai(code, file_path, "Code snippet review")
        
        all_issues = static_issues + ai_issues
        total_lines = len(code.split('\n'))
        
        score = self._calculate_score(all_issues, total_lines)
        summary = self._generate_summary(all_issues, total_lines)
        
        return ReviewResult(
            issues=all_issues,
            overall_score=score,
            summary=summary,
            total_lines_reviewed=total_lines,
            timestamp=datetime.now()
        )
    
    def _calculate_score(self, issues: List[CodeIssue], total_lines: int) -> int:
        """Calculate overall code quality score (0-100)"""
        if total_lines == 0:
            return 0
        
        # Weight issues by severity
        severity_weights = {'error': 3, 'warning': 2, 'suggestion': 1}
        total_weight = sum(severity_weights.get(issue.severity, 1) for issue in issues)
        
        # Calculate score based on issues per line
        issues_per_line = total_weight / total_lines if total_lines > 0 else 0
        
        # Convert to 0-100 scale (fewer issues = higher score)
        score = max(0, 100 - int(issues_per_line * 100))
        return min(100, score)
    
    def _generate_summary(self, issues: List[CodeIssue], total_lines: int) -> str:
        """Generate a summary of the review"""
        if not issues:
            return f"Excellent! No issues found in {total_lines} lines of code."
        
        severity_counts = {}
        category_counts = {}
        
        for issue in issues:
            severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1
            category_counts[issue.category] = category_counts.get(issue.category, 0) + 1
        
        summary_parts = [f"Reviewed {total_lines} lines of code."]
        
        if severity_counts:
            severity_summary = []
            for severity in ['error', 'warning', 'suggestion']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    severity_summary.append(f"{count} {severity}{'s' if count > 1 else ''}")
            
            if severity_summary:
                summary_parts.append(f"Found: {', '.join(severity_summary)}.")
        
        if category_counts:
            top_category = max(category_counts, key=category_counts.get)
            summary_parts.append(f"Main concern area: {top_category}.")
        
        return " ".join(summary_parts)

# Initialize the service
review_service = CodeReviewService()

# Flask Routes
@app.route('/')
def index():
    """Main dashboard"""
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/review/pr', methods=['POST'])
def review_pr():
    """API endpoint to review a pull request"""
    try:
        data = request.get_json()
        repo_url = data.get('repo_url')
        pr_number = data.get('pr_number')
        
        if not repo_url or not pr_number:
            return jsonify({'error': 'repo_url and pr_number are required'}), 400
        
        result = review_service.review_pull_request(repo_url, int(pr_number))
        
        return jsonify({
            'success': True,
            'result': {
                'overall_score': result.overall_score,
                'summary': result.summary,
                'total_lines_reviewed': result.total_lines_reviewed,
                'issues': [asdict(issue) for issue in result.issues],
                'timestamp': result.timestamp.isoformat()
            }
        })
    
    except Exception as e:
        logger.error(f"PR review failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/review/code', methods=['POST'])
def review_code():
    """API endpoint to review code snippet"""
    try:
        data = request.get_json()
        code = data.get('code')
        file_path = data.get('file_path', 'snippet.py')
        
        if not code:
            return jsonify({'error': 'code is required'}), 400
        
        result = review_service.review_code_snippet(code, file_path)
        
        return jsonify({
            'success': True,
            'result': {
                'overall_score': result.overall_score,
                'summary': result.summary,
                'total_lines_reviewed': result.total_lines_reviewed,
                'issues': [asdict(issue) for issue in result.issues],
                'timestamp': result.timestamp.isoformat()
            }
        })
    
    except Exception as e:
        logger.error(f"Code review failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/history')
def get_history():
    """Get review history"""
    try:
        limit = request.args.get('limit', 10, type=int)
        history = review_service.db.get_review_history(limit)
        return jsonify({'success': True, 'history': history})
    
    except Exception as e:
        logger.error(f"Failed to get history: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'features': {
            'static_analysis': True,
            'ai_review': bool(OPENAI_API_KEY and OPENAI_API_KEY != 'your-openai-api-key'),
            'github_integration': bool(GITHUB_TOKEN and GITHUB_TOKEN != 'your-github-token')
        }
    })

# HTML Template for Dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Code Review Assistant</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; color: white; margin-bottom: 40px; }
        .header h1 { font-size: 3rem; margin-bottom: 10px; }
        .header p { font-size: 1.2rem; opacity: 0.9; }
        .card { background: white; border-radius: 15px; padding: 30px; margin-bottom: 30px; 
                box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; font-weight: 600; color: #333; }
        .form-group input, .form-group textarea { width: 100%; padding: 12px; border: 2px solid #e1e5e9; 
                                                  border-radius: 8px; font-size: 16px; transition: border-color 0.3s; }
        .form-group input:focus, .form-group textarea:focus { outline: none; border-color: #667eea; }
        .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; 
               padding: 12px 24px; border: none; border-radius: 8px; font-size: 16px; 
               cursor: pointer; transition: transform 0.2s; }
        .btn:hover { transform: translateY(-2px); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .result { margin-top: 20px; }
        .result-header { display: flex; align-items: center; margin-bottom: 15px; }
        .score { font-size: 2rem; font-weight: bold; margin-right: 15px; }
        .score.excellent { color: #22c55e; }
        .score.good { color: #f59e0b; }
        .score.poor { color: #ef4444; }
        .issue { background: #f8f9fa; border-left: 4px solid #667eea; padding: 15px; 
                 margin-bottom: 10px; border-radius: 0 8px 8px 0; }
        .issue.error { border-left-color: #ef4444; }
        .issue.warning { border-left-color: #f59e0b; }
        .issue.suggestion { border-left-color: #6366f1; }
        .issue-header { display: flex; justify-content: between; align-items: center; margin-bottom: 8px; }
        .issue-severity { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .issue-severity.error { background: #fecaca; color: #dc2626; }
        .issue-severity.warning { background: #fed7aa; color: #ea580c; }
        .issue-severity.suggestion { background: #ddd6fe; color: #7c3aed; }
        .tabs { display: flex; margin-bottom: 20px; }
        .tab { padding: 10px 20px; background: #f1f5f9; border: none; cursor: pointer; 
               border-radius: 8px 8px 0 0; margin-right: 5px; }
        .tab.active { background: white; border-bottom: 2px solid #667eea; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .loading { text-align: center; padding: 20px; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #667eea; 
                   border-radius: 50%; width: 40px; height: 40px; 
                   animation: spin 1s linear infinite; margin: 0 auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🤖 AI Code Review Assistant</h1>
            <p>Automated code reviews powered by AI</p>
        </div>

        <div class="card">
            <div class="tabs">
                <button class="tab active" onclick="switchTab('pr')">Pull Request Review</button>
                <button class="tab" onclick="switchTab('code')">Code Snippet Review</button>
            </div>

            <div id="pr-tab" class="tab-content active">
                <h2>Review Pull Request</h2>
                <div class="form-group">
                    <label for="repo-url">Repository URL</label>
                    <input type="text" id="repo-url" placeholder="https://github.com/username/repository">
                </div>
                <div class="form-group">
                    <label for="pr-number">Pull Request Number</label>
                    <input type="number" id="pr-number" placeholder="123">
                </div>
                <button class="btn" onclick="reviewPR()">Review Pull Request</button>
            </div>

            <div id="code-tab" class="tab-content">
                <h2>Review Code Snippet</h2>
                <div class="form-group">
                    <label for="file-path">File Path (optional)</label>
                    <input type="text" id="file-path" placeholder="my_script.py">
                </div>
                <div class="form-group">
                    <label for="code-input">Code</label>
                    <textarea id="code-input" rows="10" placeholder="Paste your Python code here..."></textarea>
                </div>
                <button class="btn" onclick="reviewCode()">Review Code</button>
            </div>

            <div id="loading" class="loading" style="display: none;">
                <div class="spinner"></div>
                <p>Analyzing code...</p>
            </div>

            <div id="result" class="result" style="display: none;">
                <div class="result-header">
                    <div id="score" class="score"></div>
                    <div>
                        <h3>Review Complete</h3>
                        <p id="summary"></p>
                    </div>
                </div>
                <div id="issues"></div>
            </div>
        </div>
    </div>

    <script>
        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            document.querySelector(`[onclick="switchTab('${tab}')"]`).classList.add('active');
            document.getElementById(`${tab}-tab`).classList.add('active');
        }

        async function reviewPR() {
            const repoUrl = document.getElementById('repo-url').value;
            const prNumber = document.getElementById('pr-number').value;
            
            if (!repoUrl || !prNumber) {
                alert('Please fill in both repository URL and PR number');
                return;
            }
            
            showLoading();
            
            try {
                const response = await fetch('/api/review/pr', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ repo_url: repoUrl, pr_number: parseInt(prNumber) })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showResult(data.result);
                } else {
                    alert('Error: ' + data.error);
                }
            } catch (error) {
                alert('Network error: ' + error.message);
            } finally {
                hideLoading();
            }
        }

        async function reviewCode() {
            const code = document.getElementById('code-input').value;
            const filePath = document.getElementById('file-path').value || 'snippet.py';
            
            if (!code.trim()) {
                alert('Please enter some code to review');
                return;
            }
            
            showLoading();
            
            try {
                const response = await fetch('/api/review/code', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code: code, file_path: filePath })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showResult(data.result);
                } else {
                    alert('Error: ' + data.error);
                }
            } catch (error) {
                alert('Network error: ' + error.message);
            } finally {
                hideLoading();
            }
        }

        function showLoading() {
            document.getElementById('loading').style.display = 'block';
            document.getElementById('result').style.display = 'none';
        }

        function hideLoading() {
            document.getElementById('loading').style.display = 'none';
        }

        function showResult(result) {
            const resultDiv = document.getElementById('result');
            const scoreDiv = document.getElementById('score');
            const summaryDiv = document.getElementById('summary');
            const issuesDiv = document.getElementById('issues');
            
            // Set score and styling
            scoreDiv.textContent = result.overall_score + '/100';
            scoreDiv.className = 'score ' + getScoreClass(result.overall_score);
            
            // Set summary
            summaryDiv.textContent = result.summary;
            
            // Clear and populate issues
            issuesDiv.innerHTML = '';
            
            if (result.issues.length === 0) {
                issuesDiv.innerHTML = '<p style="text-align: center; color: #22c55e; font-weight: bold;">🎉 No issues found! Great job!</p>';
            } else {
                result.issues.forEach(issue => {
                    const issueDiv = document.createElement('div');
                    issueDiv.className = `issue ${issue.severity}`;
                    issueDiv.innerHTML = `
                        <div class="issue-header">
                            <div>
                                <span class="issue-severity ${issue.severity}">${issue.severity.toUpperCase()}</span>
                                <strong>${issue.file_path}:${issue.line_number}</strong>
                                <span style="color: #666; margin-left: 10px;">${issue.category}</span>
                            </div>
                        </div>
                        <div style="margin-bottom: 8px;"><strong>Issue:</strong> ${issue.message}</div>
                        <div><strong>Suggestion:</strong> ${issue.suggestion}</div>
                    `;
                    issuesDiv.appendChild(issueDiv);
                });
            }
            
            resultDiv.style.display = 'block';
        }

        function getScoreClass(score) {
            if (score >= 80) return 'excellent';
            if (score >= 60) return 'good';
            return 'poor';
        }
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    # Create database tables
    db = DatabaseManager(DATABASE_PATH)
    
    print("🚀 Starting AI Code Review Assistant...")
    print("📊 Dashboard available at: http://localhost:5000")
    print("🔧 API endpoints:")
    print("   POST /api/review/pr - Review pull request")
    print("   POST /api/review/code - Review code snippet")
    print("   GET /api/history - Get review history")
    print("   GET /api/health - Health check")
    print("\n⚙️  Configuration:")
    print(f"   OpenAI API: {'✅ Configured' if OPENAI_API_KEY != 'your-openai-api-key' else '❌ Not configured'}")
    print(f"   GitHub Token: {'✅ Configured' if GITHUB_TOKEN != 'your-github-token' else '❌ Not configured'}")
    print("\n🔑 To enable full functionality, set these environment variables:")
    print("   export OPENAI_API_KEY='your-actual-openai-api-key'")
    print("   export GITHUB_TOKEN='your-actual-github-token'")
    print("   export SECRET_KEY='your-secret-key'")
    
    app.run(debug=True, host='0.0.0.0', port=5000)