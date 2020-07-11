// 祖冲之序列密码算法（ZUC stream cipher algorithm）
// http://tca.iscas.ac.cn/userfiles/file/ZUC.pdf

// GMT 0001.1-2012 祖冲之序列密码算法第1部分：算法描述
// https://github.com/guanzhi/GM-Standards/blob/master/GMT%E6%AD%A3%E5%BC%8F%E6%A0%87%E5%87%86/GMT%200001.1-2012%20%E7%A5%96%E5%86%B2%E4%B9%8B%E5%BA%8F%E5%88%97%E5%AF%86%E7%A0%81%E7%AE%97%E6%B3%95%E7%AC%AC1%E9%83%A8%E5%88%86%EF%BC%9A%E7%AE%97%E6%B3%95%E6%8F%8F%E8%BF%B0.pdf
// 
// GMT 0001.2-2012 祖冲之序列密码算法第2部分：基于祖冲之算法的机密性算法
// https://github.com/guanzhi/GM-Standards/blob/master/GMT%E6%AD%A3%E5%BC%8F%E6%A0%87%E5%87%86/GMT%200001.2-2012%20%E7%A5%96%E5%86%B2%E4%B9%8B%E5%BA%8F%E5%88%97%E5%AF%86%E7%A0%81%E7%AE%97%E6%B3%95%E7%AC%AC2%E9%83%A8%E5%88%86%EF%BC%9A%E5%9F%BA%E4%BA%8E%E7%A5%96%E5%86%B2%E4%B9%8B%E7%AE%97%E6%B3%95%E7%9A%84%E6%9C%BA%E5%AF%86%E6%80%A7%E7%AE%97%E6%B3%95.pdf
// 
// GMT 0001.3-2012 祖冲之序列密码算法第3部分：基于祖冲之算法的完整性算法
// https://github.com/guanzhi/GM-Standards/blob/master/GMT%E6%AD%A3%E5%BC%8F%E6%A0%87%E5%87%86/GMT%200001.3-2012%20%E7%A5%96%E5%86%B2%E4%B9%8B%E5%BA%8F%E5%88%97%E5%AF%86%E7%A0%81%E7%AE%97%E6%B3%95%E7%AC%AC3%E9%83%A8%E5%88%86%EF%BC%9A%E5%9F%BA%E4%BA%8E%E7%A5%96%E5%86%B2%E4%B9%8B%E7%AE%97%E6%B3%95%E7%9A%84%E5%AE%8C%E6%95%B4%E6%80%A7%E7%AE%97%E6%B3%95.pdf