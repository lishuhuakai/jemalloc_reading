在看jemalloc之前,首先要学会怎么用jemalloc,怎么使用最好的参考资料在这里:

[https://www.freebsd.org/cgi/man.cgi?query=jemalloc&sektion=3](https://www.freebsd.org/cgi/man.cgi?query=jemalloc&sektion=3)

或者到官网看也行.

本人花了一定的时间,用11篇文章简单注释了一下jemalloc的主要逻辑,为了简单起见,删除了一部分不太相关的代码.当然,文章以代码为主,主要剖析了jemalloc所使用的数据结构,以及内存分配,回收,gc三大流程,没在一些细枝末节上做过多注释.

总体来说,jemalloc的代码还是相当好懂的.

我个人发现,如果读代码,不做笔记的话,和没读其实差不了太多,过了一段时间基本全部忘光了.所以后面读大型库的代码,为了提高后续再读的效率,应该都会带上一份阅读笔记.

不出意外的话,如果没有再次遇到jemalloc的相关问题,我是很难再来将jemalloc来解析一遍的,好吧,至少现在,我对这玩意应该已经很熟了.
