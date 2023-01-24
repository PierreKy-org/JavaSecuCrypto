import java.rmi.server.*;
import java.rmi.*;
import java.net.*;


public class ClassLoading {
  
  public static void main(String argv[]) throws Exception {
    ClassLoading cl = new ClassLoading();
    cl.haveARide();
  }

  String Name_of_Vehicle;

  public void haveARide() throws InstantiationException, IllegalAccessException, ClassNotFoundException, MalformedURLException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException {
    Name_of_Vehicle = "Car";
    Class car = Class.forName(Name_of_Vehicle);
    Vehicle v = (Vehicle) car.newInstance();
    v.ride();
    
    Name_of_Vehicle = "Truck";
    Class truck = RMIClassLoader.loadClass(Name_of_Vehicle);
    v = (Vehicle) truck.newInstance();
    v.ride();

    Name_of_Vehicle = "Bicycle";
    // load class bicycle with rmi remote file 
    //Pas sûr
    /* Class bicycle = RMIClassLoader.loadClass("http://localhost:8080/ClassLoaders/Bicycle.java", Name_of_Vehicle);
    v = (Vehicle) bicycle.newInstance();
    v.ride(); */

    Name_of_Vehicle = "Motorcycle";
    //Marche pas à voir pourquoi
    /*MyClassLoader MyClassLoader = new MyClassLoader();
    Class motorcycle = MyClassLoader.loadClass(Name_of_Vehicle);
    v = (Vehicle) motorcycle.newInstance();
    v.ride();*/


  }

}