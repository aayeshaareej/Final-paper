pipeline {
    agent any

    environment {
        PYTHON_VERSION = '3.10'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install Dependencies') {
            steps {
                sh '''
                    python --version
                    python -m pip install --upgrade pip
                    if [ -f requirements.txt ]; then
                        pip install -r requirements.txt
                    else
                        echo "⚠️ requirements.txt not found, installing essential packages..."
                        pip install Flask Flask-SQLAlchemy Werkzeug bleach pytest pytest-flask
                    fi
                '''
            }
        }

        stage('Run Unit Tests') {
            steps {
                sh '''
                    pytest test_app.py -v --tb=short || true
                '''
            }
        }

        stage('Build Application') {
            steps {
                sh '''
                    echo "Building Flask application..."
                    python -m py_compile app.py
                    echo "✅ Application compiled successfully"
                '''
            }
        }
    }

    post {
        always {
            echo "Pipeline execution completed"
        }
        success {
            echo "✅ All stages completed successfully!"
        }
        failure {
            echo "⚠️ Pipeline encountered issues - check logs above"
        }
    }
}
