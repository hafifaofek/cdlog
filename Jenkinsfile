pipeline {
    agent {label 'linux'}

    stages {
        stage('Checkout') {
            steps {
                // Get some code from a GitHub repository
                checkout scmGit(branches: [[name: '*/main']], extensions: [], userRemoteConfigs: [[credentialsId: '81abb510-4bb6-471e-91a3-9495e63b542a', url: 'https://github.com/hafifaofek/cdlog.git']])

            }
        }
        stage('Deploy') {
            steps {
                sh '/home/ofek/.local/bin/pyinstaller --onefile cdlog.py'
                sh 'sudo mv cdlog.conf dist/'
                sh 'sudo mkdir cdlog_package'
                sh 'sudo mv cdlog.service cdlog_package/'
                sh 'sudo mv dist/* cdlog_package/'
                sh 'sudo mv install.sh cdlog_package/'
                sh 'sudo mv README.md cdlog_package/'
                sh 'sudo chmod +x cdlog_package/install.sh'
                sh 'tar -czvf cdlog_install_package.tar.gz cdlog_package'
                sh 'sudo mv -f cdlog_install_package.tar.gz /home/ofek'
                sh 'sudo mv versions_site.html /data/index.html'
                sh 'sudo mv -f nginx.conf /etc/nginx/nginx.conf'
                sh 'sudo systemctl restart nginx'
            }
        }
        stage('Clean') {
            steps {
                // cleanWs deleteDirs: true, notFailBuild: true
                cleanWs()
                // cleanWs notFailBuild: true
            }
        }
    }
}
