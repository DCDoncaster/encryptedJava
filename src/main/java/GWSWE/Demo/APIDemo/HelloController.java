package GWSWE.Demo.APIDemo;

import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.*;

@RestController
public class HelloController {
//return a string
    @GetMapping("")
    public String hello() {
        return "Hello Team!";
    }

//return original body back
    @GetMapping("returnRequestBody")
    public String data(@RequestBody String data) {
        return data;
    }

    //param query with some maths before return
    @GetMapping("squarenumber")
    public @ResponseBody double getDouble(@RequestParam("input") double inputValue) {
        return inputValue * inputValue;
    }

    //mapping and returning only part of the initial request body
    @GetMapping("gettest")
    //returns the first key's value back as a string to the sender.
    public @ResponseBody String getTest(@RequestBody String data) {
        Gson gson = new Gson();
        Map map = gson.fromJson(data, Map.class);
        map.get("a").getClass();
        System.out.println(map.get("a"));
        return map.get("a").toString();
    }
}