//创建者：王然，    创建时间：2015.11.30
//Created by WangRan  time:2015.11.30
//本人技术不高，希望能帮到需要迅速得到自己批量本地文件在VirusTotal上的检测病毒结果的人。如有错误或您有更好的方法，请指教。
//This projection's level is very low,I just want to help someone who needs to get his or her files' virus test result from VirusTotal quickly.
//If some faults are found or you have greater solution ,please tell me,THX.
package mytry;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;

import javax.net.ssl.HttpsURLConnection;

public class FindVirResult_1 {
    //********************************将md5值传给virustotal以获得此文件的检测信息*******************************
	//********************************post MD5 to VirusTotal and get checking information***************
	public static  String getReport(String scan_id,String RETRIEVE_URL,String APIKEY) throws IOException{
		URL url = new URL(RETRIEVE_URL);
		HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
		connection.setDoOutput(true);
		connection.setRequestMethod("POST");
		OutputStream os = new DataOutputStream(connection.getOutputStream());
		StringBuilder content = new StringBuilder();
		content.append("resource=" + scan_id + "&apikey=" + APIKEY);
		os.write(content.toString().getBytes());
		os.flush();
		os.close();
		InputStream in = connection.getInputStream();//获取到返回信息,get result
		BufferedReader br = new BufferedReader(new InputStreamReader(in));
		String line;
		StringBuilder Report = new StringBuilder();
		while ((line = br.readLine()) != null) {
			Report.append(line);
			Report.append('\n');
		}
		in.close();
		br.close();
		connection.disconnect();
		return Report.toString();
	}
    //************************找出本地文件的md5值************************
	//************************find out file's md5*******************
	public static String getFileMD5(File file) {  
        if (!file.exists() || !file.isFile()) { 
            return "文件不存在";  //return  "file is not exist."
        }  
        MessageDigest digest = null;  
        FileInputStream in = null;  
        byte buffer[] = new byte[1024];  
        int len;  
        try {  
            digest = MessageDigest.getInstance("MD5");  //获取md5值,get md5
            in = new FileInputStream(file);  
            while ((len = in.read(buffer, 0, 1024)) != -1) {  
                digest.update(buffer, 0, len);  
            }  
            in.close();  
        } catch (Exception e) {  
            e.printStackTrace();  
            return "获取md5出错";  //return "error in getting md5"
        }  
        BigInteger bigInt = new BigInteger(1, digest.digest());
        String md5=bigInt.toString(16);
        if(md5.length()==31){//返回的md5值处理后可能丢掉最前面的数字“0”，此处追加。 We may lost first number "0" of md5,so check it and add "0" to first position.
        	StringBuffer changeMD5=new StringBuffer(md5);
        	md5=changeMD5.insert(0, 0).toString();	
        }
        return md5;  
    }
	//************************将检测结果写入指定文件中***************************
	//*****************write checking result into specify file*************
	public static void write_to_file(String a,String file){
		  try {
			  a=a+"\r\n";//用\n的话，在txt中不会显示换行，在notepad中可以。
			  FileOutputStream fos=new FileOutputStream(file,true);
			  fos.write(a.getBytes());//在文件末尾追加
			  fos.close();
		  	} catch (IOException e) {
		  		e.printStackTrace();
		  }

	}
		
	public static void main(String[] args){
		String RETRIEVE_URL = "https://www.virustotal.com/vtapi/v2/file/report";
//*******************************************************************************************
		 //******************     只需改下面三行内容即可         *********************************//
		 //**********You just need to modify the following three lines of codes.******//
		String APIKEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";//当你在virustotal上注册后，会获得apikey。此处需写入你自己的。yourself apikey of virustotal.When you sign in virustotal,you can get it.		
		File upload_root=new File("E:\\wangran\\wendang\\upload_vir");//你的想分析的文件的本地位置。your files location 
		String Wrote_file_location="E:\\wangran\\wendang\\upload_vir\\1.txt";//你想将结果写入的文件位置。the file location you want to write checking result into
//********************************************************************************************		
		File[] files = upload_root.listFiles();	
		int PutOutNumble=0;
		int TurnAgain=1;
		for(File file:files){			
			String md5=getFileMD5(file);  
	        String scan_id=md5;
	        PutOutNumble++;
			 try {
				String Report=getReport(scan_id,RETRIEVE_URL,APIKEY);//report是virustotal返回的全部信息，你可以将它打印出来。
				while(Report.length()<1){//会有返回报告是空的情况，而且基本上每传四个就会出现这种情况，此时重传该md5。some result may empty,upload this file again. 
					TurnAgain++;
					Report=getReport(scan_id,RETRIEVE_URL,APIKEY);
				}
				if(Report.length()>=1) TurnAgain=1;
				int i=Report.indexOf("\"total\"");			
				int j=Report.indexOf("\"sha256");
				if(i>0&&j>0){
					String Report1=Report.substring(i, j);			
					String wrote_ok=PutOutNumble+":文件名为："+file.getName()+"   结果为："+Report1+"  md5为："+md5;//String wrote_ok=PutOutNumble+":file name:"+file.getName()+"   result："+Report1+"  md5 is："+md5;
					System.out.println(wrote_ok);
					
					write_to_file(wrote_ok,Wrote_file_location);					
					System.out.println();
				}
				else if(Report.indexOf("The requested resource is not among the finished, queued or pending scans")!=-1){
					String wrote_no=PutOutNumble+":文件名为："+file.getName()+"  该文件未分析过  "+"  md5为："+md5;//String wrote_no=PutOutNumble+":file name:"+file.getName()+"  this file was not analysied  "+"  md5 is："+md5;
					System.out.println(wrote_no);
					write_to_file(wrote_no,Wrote_file_location);
					System.out.println();
				}
				else{
					String wrote_null=PutOutNumble+":文件名为："+file.getName()+"  返回字符串中没有检测信息,可能是上传信息（如md5）不对造成的。"+":  md5为："+md5+"\n"+"返回信息如下："+Report+".";//String wrote_null=PutOutNumble+":file name:"+file.getName()+"  there is no right analysis result in string got from virustotal,something was wrong."+":  md5 is："+md5+"\n"+"information from virustotal is："+Report+".";
					System.out.println(wrote_null);
					write_to_file(wrote_null,Wrote_file_location);
					System.out.println();
				}
			} catch (IOException e) {
				e.printStackTrace();			
			}
		}	 
	}
}
