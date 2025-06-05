# CodeSense-AI

### Prerequisites
- Python 3.8+
- OpenAI API key (optional, for AI-powered reviews)
- GitHub Personal Access Token (optional, for PR reviews)

### Installation

1. **Clone or create the project directory:**
```bash
mkdir ai-code-review-assistant
cd ai-code-review-assistant
```

2. **Create and activate virtual environment:**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Set up environment variables:**
```bash
cp .env.example .env
# Edit .env file with your actual API keys
```

5. **Run the application:**
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## 🔧 Configuration

### Environment Variables

Create a `.env` file with the following variables:

```bash
# Required for AI reviews
OPENAI_API_KEY=your-openai-api-key

# Required for GitHub PR reviews
GITHUB_TOKEN=your-github-personal-access-token

# Required for security
SECRET_KEY=your-random-secret-key

# Optional configurations
DATABASE_PATH=./data/code_reviews.db
FLASK_ENV=production
```

### Getting API Keys

#### OpenAI API Key
1. Go to [OpenAI Platform](https://platform.openai.com/)
2. Create an account or sign in
3. Navigate to API Keys section
4. Create a new API key
5. Copy the key to your `.env` file

#### GitHub Personal Access Token
1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Click "Generate new token (classic)"
3. Select scopes: `repo` (for private repos) or `public_repo` (for public repos)
4. Copy the token to your `.env` file

## 🐳 Docker Deployment

### Using Docker Compose (Recommended)

1. **Create docker-compose.yml** (already provided in the setup files)

2. **Create .env file** with your configuration

3. **Build and run:**
```bash
docker-compose up -d
```

4. **Check logs:**
```bash
docker-compose logs -f
```

### Using Docker directly

```bash
# Build the image
docker build -t ai-code-review .

# Run the container
docker run -d \
  -p 5000:5000 \
  -e OPENAI_API_KEY=your-key \
  -e GITHUB_TOKEN=your-token \
  -e SECRET_KEY=your-secret \
  -v $(pwd)/data:/app/data \
  ai-code-review
```

## 📝 Usage

### Web Interface

1. **Navigate to** `http://localhost:5000`
2. **Choose review type:**
   - **Pull Request Review:** Enter GitHub repo URL and PR number
   - **Code Snippet Review:** Paste code directly

### API Endpoints

#### Review Pull Request
```bash
curl -X POST http://localhost:5000/api/review/pr \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/username/repository",
    "pr_number": 123
  }'
```

#### Review Code Snippet
```bash
curl -X POST http://localhost:5000/api/review/code \
  -H "Content-Type: application/json" \
  -d '{
    "code": "def hello():\n    print(\"Hello World\")",
    "file_path": "hello.py"
  }'
```

#### Get Review History
```bash
curl http://localhost:5000/api/history?limit=10
```

#### Health Check
```bash
curl http://localhost:5000/api/health
```

## 🔍 Features

### Static Code Analysis
- **Security Issues:** Detects dangerous functions, command injection risks
- **Performance Problems:** Identifies inefficient patterns
- **Style Issues:** Checks for code style and best practices
- **Logic Problems:** Finds potential bugs and issues
- **Documentation:** Checks for missing docstrings

### AI-Powered Review
- **Intelligent Analysis:** Uses OpenAI GPT for advanced code understanding
- **Context-Aware:** Considers the overall code context
- **Specific Suggestions:** Provides actionable improvement recommendations

### GitHub Integration
- **Pull Request Analysis:** Automatically fetches and reviews PR changes
- **Multi-file Support:** Reviews all Python files in a PR
- **Change Tracking:** Focuses on modified code

### Web Dashboard
- **Interactive Interface:** Easy-to-use web interface
- **Real-time Results:** Instant feedback on code quality
- **Issue Categorization:** Organized by severity and type
- **Score System:** Overall code quality score (0-100)

## 🛠️ Development

### Running Tests
```bash
pytest tests/
```

### Code Formatting
```bash
black app.py
flake8 app.py
```

### Type Checking
```bash
mypy app.py
```

### Security Scanning
```bash
bandit -r .
```

## 📊 Extending the Application

### Adding New Languages

1. **Create a new analyzer class:**
```python
class JavaScriptAnalyzer:
    def analyze_code(self, code: str, file_path: str) -> List[CodeIssue]:
        # Implement JavaScript-specific analysis
        pass
```

2. **Update the service to use the new analyzer:**
```python
def review_file(self, content: str, file_path: str):
    if file_path.endswith('.js'):
        return self.js_analyzer.analyze_code(content, file_path)
    elif file_path.endswith('.py'):
        return self.py_analyzer.analyze_code(content, file_path)
```

### Adding New Issue Types

1. **Extend the CodeIssue dataclass if needed**
2. **Add new patterns to the analyzer**
3. **Update the AI prompt to look for new issue types**

### Integration with CI/CD

Create a webhook endpoint:
```python
@app.route('/webhook/github', methods=['POST'])
def github_webhook():
    # Handle GitHub webhook events
    # Automatically review PRs when created/updated
    pass
```

## 🔒 Security Considerations

- **API Keys:** Store securely, never commit to version control
- **Input Validation:** All user inputs are validated
- **SQL Injection:** Uses parameterized queries
- **Rate Limiting:** Consider adding rate limiting for production
- **HTTPS:** Use HTTPS in production environments

## 🚀 Production Deployment

### Environment Setup
- Use production WSGI server (Gunicorn)
- Set up reverse proxy (Nginx)
- Configure SSL certificates
- Set up monitoring and logging

### Example Gunicorn Configuration
```bash
gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
```

### Scaling Considerations
- Use Redis for caching frequent requests
- Implement queue system for long-running reviews
- Consider horizontal scaling with load balancer

## 📈 Monitoring

### Health Checks
The application provides a health check endpoint at `/api/health` that reports:
- Service status
- Feature availability
- Database connectivity

### Logging
All operations are logged with appropriate levels:
- INFO: Normal operations
- WARNING: Potential issues
- ERROR: Failed operations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## 📄 License

This project is open source. Feel free to use and modify as needed.

## 🆘 Troubleshooting

### Common Issues

**Issue:** "OpenAI API key not configured"
**Solution:** Set the `OPENAI_API_KEY` environment variable

**Issue:** "GitHub token invalid"
**Solution:** Check your GitHub token has the required permissions

**Issue:** "Database locked"
**Solution:** Ensure only one instance is running or use a different database

**Issue:** "Port already in use"
**Solution:** Change the port in app.py or kill the process using the port

### Getting Help

1. Check the logs for detailed error messages
2. Ensure all environment variables are set correctly
3. Verify API keys have the required permissions
4. Check GitHub repository permissions for PR reviews

## 🎯 Roadmap

- [ ] Support for more programming languages
- [ ] Integration with GitLab and Bitbucket
- [ ] Advanced reporting and analytics
- [ ] Team collaboration features
- [ ] Custom rule configuration
- [ ] Plugin system for extensibility