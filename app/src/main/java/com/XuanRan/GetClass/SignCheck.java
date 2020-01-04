package com.XuanRan.GetClass;

/**
 * Create By XuanRan 2019/02/04
 */
import android.content.*;
import android.content.pm.*;
import android.util.*;
import dalvik.system.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import android.content.pm.Signature;
import android.util.Base64;
//签名验证工具
public class SignCheck
{
    private Context context;
    private String cer = null;
	/*
	 * param 0:cc.binmt.signature.PmsHookApplication
	 * param 1:cn.wjdiankong.hookpms.ServiceManagerWraper
	 * 
	 */
	private String bxHookClass[]={"Y2MuYmlubXQuc2lnbmF0dXJlLlBtc0hvb2tBcHBsaWNhdGlvbg==","Y24ud2pkaWFua29uZy5ob29rcG1zLlNlcnZpY2VNYW5hZ2VyV3JhcGVy",};
	/*
	 * param:用户自定义的Hook类
	 */
	private String HookClass[]={"","","","","","","","","","","","","","","","","","","","","","","",""};
	private List<String> hookclasslist;
    private String realCer = null;
    private static final String TAG = "SignCheck";

	/*
	 *   Base64转换String
	 *   Creat:XuanRan
	 */

	public String Base64ToString(String hi)
	{
		byte[] by=Base64.decode(hi, 0);
		String string=new String(by);
		return string;
	}
	/*
	 *   寻找Hook Class
	 */
	public void FindHookClass()
	{

		for (int xr=0;xr < hookclasslist.size();xr++)
		{
			//  param 查找的包名路径
			List<String >classNameList=getClassName(hookclasslist.get(xr), context);
			for (int i=0;i < classNameList.size();i++)
			{
				//通过循环对比数组来检查是否存在
				if (hookclasslist.contains(classNameList.get(i)))
				{
					kill();
				}				
			}
		}
	}
	/*
	 *   结束程序进程
	 */
	protected void kill()
	{
		Log.e(Base64ToString("WHVhblJhblJ1blRpbWVFeGNlcHRpb24="), Base64ToString("UHJvaGliaXRlZCBDbGFzczo="));
		int ip=android.os.Process.myPid();
		android.os.Process.killProcess(ip);		
	}
    public SignCheck(Context context)
	{
        this.context = context;
        this.cer = getCertificateSHA1Fingerprint();
    }

    public SignCheck(Context context, String realCer)
	{
        this.context = context;
        this.realCer = realCer;
        this.cer = getCertificateSHA1Fingerprint();

		//检查是否是第一次使用 减少资源浪费
		if (!isNotFirst("WHVhblJhbkNoZWNrU2lnblNoYXJlZEJvb2xlYW4"))
		{
			hookclasslist = new ArrayList<String >();
			//忽略bxHookClass数组中的空白内容
			for (int xr=0;xr < bxHookClass.length;xr++)
			{
				if (!bxHookClass[xr].equals(""))
				{
					//解密bxhookclass数组内容并添加到hookclasslist中
					hookclasslist.add(Base64ToString(bxHookClass[xr]));
				}
			}
			//用户自定义需要检查的class，忽略hookClass中的空白内容
			for (int xr=0;xr < HookClass.length;xr++)
			{
				//检查HookClass数组中是否存在空值
				if (!HookClass[xr].equals(""))
				{
					//如果不是空值则检查hookclasslist是否已经存在
					if (!hookclasslist.contains(HookClass[xr]))
					{
						//将非空值和未重复的添加到hookclasslist数组。
						hookclasslist.add(HookClass[xr]);
					}

				}
			}
			hookclasslist.add(context.getPackageName() + ".PmsHook");
			//寻找HookClass列表
			FindHookClass();
			//在创建构造方法时就开始检查签名
			if (!check())
			{
				kill();
			}
		}
    }

    public String getRealCer()
	{
        return realCer;
    }

    /**
     * 设置正确的签名
     *
     * @param realCer
     */
    public void setRealCer(String realCer)
	{
        this.realCer = realCer;
    }

    /**
     * 获取应用的签名
     *
     * @return
     */
    public String getCertificateSHA1Fingerprint()
	{
        //获取包管理器
        PackageManager pm = context.getPackageManager();

        //获取当前要获取 SHA1 值的包名，也可以用其他的包名，但需要注意，
        //在用其他包名的前提是，此方法传递的参数 Context 应该是对应包的上下文。
        String packageName = context.getPackageName();

        //返回包括在包中的签名信息
        int flags = PackageManager.GET_SIGNATURES;

        PackageInfo packageInfo = null;

        try
		{
            //获得包的所有内容信息类
            packageInfo = pm.getPackageInfo(packageName, flags);
        }
		catch (PackageManager.NameNotFoundException e)
		{
            e.printStackTrace();
        }

        //签名信息
        Signature[] signatures = packageInfo.signatures;
        byte[] cert = signatures[0].toByteArray();

        //将签名转换为字节数组流
        InputStream input = new ByteArrayInputStream(cert);

        //证书工厂类，这个类实现了出厂合格证算法的功能
        CertificateFactory cf = null;

        try
		{
            cf = CertificateFactory.getInstance("X509");
        }
		catch (Exception e)
		{
            e.printStackTrace();
        }

        //X509 证书，X.509 是一种非常通用的证书格式
        X509Certificate c = null;

        try
		{
            c = (X509Certificate) cf.generateCertificate(input);
        }
		catch (Exception e)
		{
            e.printStackTrace();
        }

        String hexString = null;

        try
		{
            //加密算法的类，这里的参数可以使 MD4,MD5 等加密算法
            MessageDigest md = MessageDigest.getInstance("SHA1");

            //获得公钥
            byte[] publicKey = md.digest(c.getEncoded());

            //字节到十六进制的格式转换
            hexString = byte2HexFormatted(publicKey);

        }
		catch (NoSuchAlgorithmException e1)
		{
            e1.printStackTrace();
        }
		catch (CertificateEncodingException e)
		{
            e.printStackTrace();
        }
        return hexString;
    }

    /*
	 * 格式转换
	 * Create:XuanRan
	 * https://dwz.cn/QQ3135
	 * MT论坛：bbs.binmt.cc
	 */
    private String byte2HexFormatted(byte[] arr)
	{
        StringBuilder str = new StringBuilder(arr.length * 2);

        for (int i = 0; i < arr.length; i++)
		{
            String h = Integer.toHexString(arr[i]);
            int l =h.length();
            if (l == 1)
                h = "0" + h;
            if (l > 2)
                h = h.substring(l - 2, l);
            str.append(h.toUpperCase());
            if (i < (arr.length - 1))
                str.append(':');
        }
        return str.toString();
    }

	/* 
	 *  获取类
	 */
	public List<String > getClassName(String packageName, Context context)
	{

        List<String >classNameList=new ArrayList<String >();
        try
		{

            DexFile df = new DexFile(context.getPackageCodePath());//通过DexFile查找当前的APK中可执行文件
            Enumeration<String> enumeration = df.entries();//获取df中的元素  这里包含了所有可执行的类名 该类名包含了包名+类名的方式
            while (enumeration.hasMoreElements())
			{//遍历
                String className = (String) enumeration.nextElement();

                if (className.contains(packageName))
				{//在当前所有可执行的类里面查找包含有该包名的所有类
                    classNameList.add(className);
                }
            }
        }
		catch (Exception e)
		{
            e.printStackTrace();
        }
        return  classNameList;
    }

	/* 
	 * 检查是否为第一次使用，减少系统资源浪费
	 *
	 */

	public boolean isNotFirst(String a)
	{
		SharedPreferences shared=context.getSharedPreferences(Base64ToString("WHVhblJhbkNoZWNrU2lnblNoYXJlZFBGaWxl"), Context.MODE_PRIVATE);
		return shared.getBoolean(Base64ToString(a), false);
	}

	public void putNotfirst()
	{
		SharedPreferences shared=context.getSharedPreferences(Base64ToString("WHVhblJhbkNoZWNrU2lnblNoYXJlZFBGaWxl"), Context.MODE_PRIVATE);
		SharedPreferences.Editor sharededit=shared.edit();
		sharededit.putBoolean(Base64ToString("WHVhblJhbkNoZWNrU2lnblNoYXJlZEJvb2xlYW4="), true);
		sharededit.commit();
	}
    /**
     * 检测签名是否正确
     * @return true 签名正常 false 签名不正常
     */
    public boolean check()
	{
		boolean reboln=false;
		boolean xuanranboolean=isNotFirst("WHVhblJhbkNoZWNrU2lnblNoYXJlZEJvb2xlYW4=");
		if (reboln)
		{
			kill();
		}
		if (this.realCer != null)
		{
			cer = cer.trim();
			realCer = realCer.trim();
			if (this.cer.equals(this.realCer))
			{
				reboln = true;
				if (!xuanranboolean)
				{
					putNotfirst();
				}
				return reboln;
			}

		}
		else
		{
			Log.e(Base64ToString("WHVhblJhblJ1blRpbWVFeGNlcHRpb24="), Base64ToString("5pyq57uZ5a6a55yf5a6e55qE562+5ZCNIFNIQS0xIOWAvA=="));
		}
		return reboln;

	}}
