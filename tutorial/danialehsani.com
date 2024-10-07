server {
        listen 80;
        listen [::]:80;

        root /var/www/danialehsani.com/html;
        index index.html index.htm index.nginx-debian.html;

        server_name danialehsani.com www.danialehsani.com;

        location / {
                try_files $uri $uri/ =404;
        }
}
