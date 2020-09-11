package dev.lab3;

@RestController
@RequestMapping(value = "/server")
public class ServerController {
    @RequestMapping(value = "/data", method = RequestMethod.GET)
    public String getData() {
        System.out.println("Returning data from server");
        return "Hello from server";
    }
}
