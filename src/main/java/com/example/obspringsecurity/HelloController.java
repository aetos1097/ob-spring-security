package com.example.obspringsecurity;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/hola")
    public String holaMundo(){
        return "Hola Mundo que tal vamos!! Hasta luego";
    }
    @GetMapping("/bootstrap")
    public String bootstrap(){
      return """
              <!doctype html>
              <html lang="ar" dir="rtl">
                <head>
                  <!-- Required meta tags -->
                  <meta charset="utf-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1">
                            
                  <!-- Bootstrap CSS -->
                  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.rtl.min.css" integrity="sha384-WJUUqfoMmnfkBLne5uxXj+na/c7sesSJ32gI7GfCk4zO4GthUKhSEGyvQ839BC51" crossorigin="anonymous">
                            
                  <title>Hello word</title>
                </head>
                <body>
                  <h1 align="center">Mi primer APP desde Spring</h1>
                  <a class = "btn btn-primary" href = "https://www.google.com">Google</a>
                            
                  <!-- Optional JavaScript; choose one of the two! -->
                            
                  <!-- Option 1: Bootstrap Bundle with Popper -->
                  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script>
                            
                  <!-- Option 2: Separate Popper and Bootstrap JS -->
                  <!--
                  <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js" integrity="sha384-oBqDVmMz9ATKxIep9tiCxS/Z9fNfEXiDAYTujMAeBAsjFuCZSmKbSSUnQlmh/jp3" crossorigin="anonymous"></script>
                  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.min.js" integrity="sha384-mQ93GR66B00ZXjt0YO5KlohRA5SY2XofN4zfuZxLkoj1gXtW8ANNCe9d5Y3eG5eD" crossorigin="anonymous"></script>
                  -->
                </body>
              </html>
              """;
    }

}
