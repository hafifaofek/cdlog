pipeline {
    agent {label 'linux'}

    stages {
        stage('Checkout') {
            steps {
                // Get some code from a GitHub repository
                checkout scmGit(branches: [[name: '*/main']], extensions: [], userRemoteConfigs: [[credentialsId: '81abb510-4bb6-471e-91a3-9495e63b542a', url: 'https://github.com/hafifaofek/cdlog.git']])

            }
        }
        stage('compile') {
            steps {
                sh '/home/ofek/.local/bin/pyinstaller --onefile cdlog.py'
            }
        }
        stage('Deploy tar') {
            steps {
                sh 'sudo cp cdlog.conf /home/ofek'
                sh 'sudo cp cdlog.conf dist/'
                sh 'sudo mkdir cdlog_package'
                sh 'sudo cp cdlog.service cdlog_package/'
                sh 'sudo cp dist/* cdlog_package/'
                sh 'sudo cp install.sh cdlog_package/'
                sh 'sudo cp README.md cdlog_package/'
                sh 'sudo chmod +x cdlog_package/install.sh'
                sh 'tar -czvf cdlog_install_package.tar.gz cdlog_package'
                sh 'sudo cp -f cdlog_install_package.tar.gz /home/ofek'
                sh 'sudo cp versions_site.html /data/index.html'
                sh 'sudo cp logo.jpg /data'
                sh 'sudo cp -f nginx.conf /etc/nginx/nginx.conf'
                sh 'sudo cp try.py /home/ofek'
                sh 'sudo systemctl restart nginx'
            }
        }
        stage('Deploy rpm') {
            steps {
                sh 'sudo mkdir my_rpm_project'
                sh 'sudo mkdir my_rpm_project/BUILD'
                sh 'sudo mkdir my_rpm_project/RPMS'
                sh 'sudo mkdir my_rpm_project/SOURCES'
                sh 'sudo mkdir my_rpm_project/SPECS'
                sh 'sudo mkdir my_rpm_project/SRPMS'
                sh 'sudo cp dist/cdlog my_rpm_project/SOURCES'
                sh 'sudo cp cdlog.conf my_rpm_project/SOURCES'
                sh 'sudo cp cdlog.service my_rpm_project/SOURCES'
                sh 'sudo cp dist/cdlog linux/rpm'
                sh 'sudo cp dist/cdlog /root/rpmbuild/SOURCES'
                sh 'sudo cp dist/cdlog cdlog'
                sh 'sudo rpmbuild --define "_sourcedir $(pwd)" -ba linux/rpm/rpm.spec'
                sh 'sudo cp rpm.rpm /home/ofek'
            }
        }
        stage('Clean') {
            steps {
                // cleanWs deleteDirs: true, notFailBuild: true
                // cleanWs()
                cleanWs notFailBuild: true

            }
        }
    }
}
