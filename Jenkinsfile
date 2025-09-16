pipeline {
    agent any

    stages {
        stage('Clone Repository') {
            steps {
                git branch: 'main', url: 'https://github.com/gulshan4kainth/tatou.git'
            }
        }

        stage('Deploy with Docker Compose') {
            steps {
                // Make sure Docker and Docker Compose are installed on your Jenkins agent
                sh 'docker compose down'          // stop old containers if any
                sh 'docker compose pull'          // pull latest images
                sh 'docker compose up --build -d' // start containers
            }
        }
    }

    post {
        success {
            echo 'Deployment completed successfully!'
        }
        failure {
            echo 'Deployment failed!'
        }
    }
}
