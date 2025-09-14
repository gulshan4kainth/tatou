pipeline {
  agent any
  options { timestamps(); ansiColor('xterm') }
  tools { git 'Default' }

  stages {
    stage('Checkout') {
      steps { checkout scm }
    }

    stage('Set up venv') {
      steps {
        sh '''
          python3 -m venv .venv
          . .venv/bin/activate
          pip install -U pip
          pip install -r requirements.txt || true
          pip install pytest pytest-cov flake8 bandit
        '''
      }
    }

    stage('Lint & SAST') {
      steps {
        sh '''
          . .venv/bin/activate
          flake8 .
          bandit -r . -q
        '''
      }
    }

    stage('Test') {
      steps {
        sh '''
          . .venv/bin/activate
          mkdir -p test-results
          pytest -q --junitxml=test-results/junit.xml --cov=. --cov-report=xml
        '''
      }
      post {
        always {
          junit 'test-results/junit.xml'
          publishCoverage adapters: [coberturaAdapter('coverage.xml')]
        }
      }
    }

    stage('Build Docker (optional)') {
      when { expression { fileExists('Dockerfile') } }
      steps {
        sh '''
          IMAGE="${JOB_NAME// /-}:${BUILD_NUMBER}"
          echo "Building $IMAGE"
          docker build -t "$IMAGE" .
          echo $IMAGE > image.txt
        '''
      }
      post { success { archiveArtifacts 'image.txt' } }
    }

    stage('Deploy (demo, optional)') {
      when { expression { fileExists('image.txt') } }
      steps {
        sh '''
          IMAGE="$(cat image.txt)"
          docker rm -f school-demo || true
          # expose your app on 8000 inside the container
          docker run -d --name school-demo -p 8000:8000 "$IMAGE"
        '''
      }
    }
  }

  post { always { cleanWs() } }
}
