pipeline {
  agent any
  options { timestamps(); ansiColor('xterm') }

  environment {
    COMPOSE_PROJECT_NAME = 'tatou'
    COMPOSE_FILE = 'docker-compose.yml'   // adjust if different
  }

  stages {
    stage('Checkout') {
      steps {
        // Prefer Pipeline-from-SCM job config; if not, use this:
        git branch: 'main', url: 'https://github.com/gulshan4kainth/tatou.git'
      }
    }

    stage('Preflight') {
      steps {
        sh '''
          set -e
          whoami
          docker --version
          docker compose version
        '''
      }
    }

    stage('Build') {
      steps {
        sh '''
          set -e
          docker compose build --pull
        '''
      }
    }

    stage('Test') {
      steps {
        sh '''
          set -e
          # Run tests in the app container; adjust service/name & test path
          docker compose run --rm server pytest -q server/tests || \
          docker compose run --rm server pytest -q server/test
        '''
      }
    }

    stage('Deploy') {
      steps {
        sh '''
          set -e
          docker compose down
          docker compose up -d
        '''
      }
    }
  }

  post {
    failure {
      // Show last logs to help debugging failed builds
      sh 'docker compose logs --no-color --tail=200 || true'
    }
    always {
      // Keep workspace clean between builds
      cleanWs()
    }
  }
}
