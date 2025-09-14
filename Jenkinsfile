pipeline {
  agent any
  options { timestamps() }

  environment {
    COMPOSE_PROJECT_NAME = "tatou"
    COMPOSE_FILE = "docker-compose.yml"
  }

  stages {
    stage('Checkout') {
      steps {
        git branch: 'main', url: 'https://github.com/your-repo/tatou.git'
      }
    }

    stage('Build') {
      steps {
        wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
          sh 'docker compose build --pull'
        }
      }
    }

    stage('Test') {
      steps {
        wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
          // adjust service name and test path to match your docker-compose.yml
          sh 'docker compose run --rm server pytest -q server/tests'
        }
      }
    }

    stage('Deploy') {
      steps {
        wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
          sh '''
            docker compose down
            docker compose up -d
          '''
        }
      }
    }
  }

  post {
    failure {
      wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
        sh 'docker compose logs --no-color --tail=200 || true'
      }
    }
    always {
      cleanWs()
    }
  }
}
