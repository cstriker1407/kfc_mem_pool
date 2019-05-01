pipeline {
  agent any
  stages {
    stage('BUILD') {
      agent any
      steps {
        echo 'Hello First Step'
        sleep 2
        input(message: 'YES or NO', id: '1', ok: 'YES')
      }
    }
  }
}