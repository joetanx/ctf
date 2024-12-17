<!DOCTYPE html>
<?php
  if (isset($_FILES['file']))
  {
    $target_dir='uploads/';
    $target_file=$target_dir.$_FILES['file']['name'];
    move_uploaded_file($_FILES['file']['tmp_name'],$target_file);
    echo basename($_FILES['file']['name']).' uploaded.';
  }
?>
<html>
  <head/>
  <body>
    <form action='upload.php' method='POST' enctype='multipart/form-data'>
      <br><br>
      Select a file to upload:
      <br><br><br>
      <input type='file' name='file'>
      <br><br><br>
      <input type='submit' name='submit'>
    </form>
  </body>
</html>
