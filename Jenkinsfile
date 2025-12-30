pipeline {
    agent any

    environment {
        PYTHON_VERSION = '3.9'
    }

    stages {
        stage('Clone Repository') {
            steps {
                git branch: 'main',
                    credentialsId: 'github-creds',
                    url: 'https://github.com/aayeshaareej/Final-paper.git'
            }
        }

        stage('Install Dependencies') {
            steps {
                sh '''
                    python -m pip install --upgrade pip
                    pip install -r requirements.txt
                '''
            }
        }

        stage('Run Unit Tests') {
            steps {
                sh '''
                    pytest test_app.py -v --tb=short
                '''
            }
        }

        stage('Code Quality Check') {
            steps {
                sh '''
                    pip install pylint
                    pylint app.py --disable=all --enable=E || true
                '''
            }
        }

        stage('Build Application') {
            steps {
                echo "Building Flask application..."
                sh '''
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
            echo "✅ All stages passed successfully!"
        }
        failure {
            echo "❌ Pipeline failed! Check logs above."
        }
    }
}
