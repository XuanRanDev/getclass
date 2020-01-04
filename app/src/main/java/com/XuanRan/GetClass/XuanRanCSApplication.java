package com.XuanRan.GetClass;

import android.app.*;
import android.content.*;
import android.util.*;

public final class XuanRanCSApplication extends Application
{
	/*
	 * Create:XuanRan  2019/02/04
	 * MT论坛：bbs.binmt.cc
	 * 在您转载源代码时 请注明出处
	 */
	protected boolean isNotneedBase64Jiami=true;
	protected SignCheck signCheck;
	protected String JKS_SHA_A="9E:B3:94:54:C0:60:71:78:16:8A:61:F8:87:99:CB:A3:F0:70:B1:8F";

    protected void attachBaseContext(Context base)
	{
			signCheck = new SignCheck(base, JKS_SHA_A);
			if (!isNotneedBase64Jiami)
			{
				try
				{
					signCheck = new SignCheck(base, signCheck.Base64ToString(JKS_SHA_A));
				}
				catch (Exception e)
				{
					e.printStackTrace();
					Log.e("XuanRanRunTimeException", "Error!");
				}
			}
			if (!signCheck.check())
			{
				int ip=android.os.Process.myPid();
				android.os.Process.killProcess(ip);
				Log.e(signCheck.Base64ToString("WHVhblJhblJ1blRpbWVFeGNlcHRpb24="), signCheck.Base64ToString("SktTIFNIQS0xIEVycm9y77yB"));
			}
			super.attachBaseContext(base);
    }

}

