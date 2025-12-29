pipeline {
    agent any
    
    parameters {
        string(name: 'BUILD_ENV', defaultValue: 'development', description: 'Build environment (development/production)')
        booleanParam(name: 'ENABLE_TESTS', defaultValue: true, description: 'Enable or disable test stage')
        choice(name: 'LOG_LEVEL', choices: ['INFO', 'DEBUG', 'ERROR'], description: 'Log level for the build')
    }
    
    stages {
        stage('Build') {
            steps {
                echo 'Building..'
                echo "Build Environment: ${params.BUILD_ENV}"
                echo "Log Level: ${params.LOG_LEVEL}"
                // Here you can define commands for your build
            }
        }
        
        stage('Test') {
            when {
                expression {
                    return params.ENABLE_TESTS == true
                }
            }
            steps {
                echo 'Testing..'
                echo 'Tests are enabled and running...'
                // Here you can define commands for your tests
            }
        }
        
        stage('Deploy') {
            steps {
                echo 'Deploying....'
                // Here you can define commands for your deployment
            }
        }
    }
    
    post {
        always {
            echo 'This will always run after all stages'
        }
        failure {
            echo 'This will run only if the pipeline fails'
        }
    }
}
