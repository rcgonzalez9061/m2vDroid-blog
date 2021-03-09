---
layout: page
title: m2vDroid
permalink: /
---

{% include head.html %}

# m2vDroid: Attacking the HinDroid Malware Detector

## INTRODUCTION

Over the past decade, malware has established itself as a constant issue for the Android operating system. In 2018, Symantec reported that they blocked more than 10 thousand malicious Android apps per day, while nearly 3 quarters of Android devices remained on older versions of Android. With billions of active Android devices, millions are only a swipe away from becoming victims. Naturally, automated machine learning-based detection systems have become commonplace solutions as they can drastically speed up the labeling process. However, it has been shown that many of these models are vulnerable to adversarial attacks, notably attacks that add redundant code to malware to consfuse detectors. 

In our project, we introduce a new model that extends the [Hindroid detection system](https://www.cse.ust.hk/~yqsong/papers/2017-KDD-HINDROID.pdf) by employing node embeddings using [metapath2vec](https://ericdongyx.github.io/papers/KDD17-dong-chawla-swami-metapath2vec.pdf) which we call m2vDroid. We believe that the introduction of node embeddings will improve the performance of the model beyond the capabilities of HinDroid. Second, we attempt to attack these models with adversarial machine learning using a method similar to that proposed in  the paper [Android HIV](https://ieeexplore.ieee.org/document/8782574). Specifically, we aim to find a way to add small changes to malware so that it may evade a detector. We hope that this will serve as a first step to determining the robustness of these models against adversarial attacks.

### Preliminaries
Before we get into details, there are a few concepts that we should familiarize with:

- *Definition 1)* A **Heterogeneous Information Network (HIN)** is a graph in which its nodes and edges have different types. 

- *Definition 2)* A **Metapath** is a path within a HIN that follows certain node types. For example, let us define a HIN with a set of node types $T$ and a path $P = n_1 \longrightarrow n_2 \longrightarrow ... \longrightarrow n_{N}$ of length $N$. $P$ follows metapath $M_P = t_1 \longrightarrow t_2 \longrightarrow ... \longrightarrow t_{N}$ if $type(n_i) = t_i$ for all $i \in [1,2,...,N]$.

## PREVIOUS WORKS
We also reference a few papers, so to fill you in we've summarized them below.
 
### Hindroid (2017)
Hindroid is a malware detection system developed by Hou, et al, and served as a basis for our model, m2vDroid. In it, they "represent Android apps, related APIs, and their rich relations as a heterogeneous information network" and were one of the first to apply this method for the detection of malware. To build their heterogeneous information network, they unpack and decompile Android apps into the readable `smali` format and extract information for each API call (Notably, their code block, package, and invoke method). With this data, they construct 4 matrices which serve as adjacency matrices for Apps and APIs in the heterogeneous information network:

<br>
<br>

<table>
    <tr>
        <th colspan=3> <b>Description of Each Matrix</b></th>
    </tr>
    <tr>
        <th><b>G</b></th>
        <th>Element</th>
        <th>Description</th>
    </tr>
    <tr>
        <td><b>A</b></td>
        <td> $a_{i,j}$ </td>
        <td> If $app_i$ contains $API_j$, then $a_{i,j} = 1$;<br> otherwise, $a_{i,j} = 0$.</td>
    </tr>
    <tr>
        <td><b>B</b></td>
        <td> $b_{i,j}$ </td>
        <td> If $API_i$ and $API_j$ co-exist in the same block, then $b_{i,j} = 1$;<br> otherwise, $b_{i,j} = 0$.</td>
    </tr>
    <tr>
        <td><b>P</b></td>
        <td> $p_{i,j}$ </td>
        <td> If $API_i$ and $API_j$ have the same package name, then $p_{i,j} = 1$;<br> otherwise, $p_{i,j} = 0$.</td>
    </tr>
    <tr>
        <td><b>I</b></td>
        <td> $i_{i,j}$ </td>
        <td> If $API_i$ and $API_j$ have the same invocation type, then $i_{i,j} = 1$;<br> otherwise, $i_{i,j} = 0$.</td>
    </tr>
</table>

Using these relationships, they form metapaths between all apps. For example, the metapath $App \xrightarrow{contains}API\xrightarrow{contains^{-1}}App$ which is captured by the $AA^T$ kernel. Other kernels they consider include $ABA^T$, $APA^T$, $ABPB^TA^T$, and $APBP^TA^T$. For $n$ apps, this produces $n \times n$ matrices — for each metapath — where the value at index $[i,j]$ is the number of paths connecting $App_i$ with $App_j$ for that metapath. Therefore, each row in the matrix is the feature vector for an app with the number of metapaths between it and all other apps in the training set. Each matrix then forms a kernel for a support vector machine and with multi-kernel learning they were able to achieve performances ranging from a $0.948$ F1-score to $0.988$ with the multi-kernel model.

### Android HIV
In this paper, the authors, Chen et al., introduce a framework for attacking malware detection models, specifically the MamaDroid and Drebin systems. To perform this, they modified two adversarial attack algorithms: a modified Carlini and Wagner (C&W) attack and a modified Jacobian Saliency Map Attack (JSMA). These modified algorithms were used to generate perturbations that were added into the features of apps so that they were misclassified as benign all while keeping the apps as functional examples of malware. With these methods, they were able to reduce the performance of both the MamaDroid and Drebin malware from detection rates of more than $95\%$ to $1\%$. In our project, we adapt their methods in order to attack the HinDroid system and our model, m2vDroid.

## METHODOLOGY
## m2vDroid
m2vDroid is our take on HinDroid but we've added a spin to it. We apply the metapath2vec algorithm to generate vectors that represent the apps in our graph. We can break down metapath2vec into 2 key steps. 
 
**Step 1 - The Random Walk)** In essence, we take the HinDroid graph structure and perform *random metapath walks* throughout it. Basically, we just traverse the graph following a specific pattern of nodes, recording the nodes we find along the way. It is "random" because when we visit a node, we choose a random neighbor that is the same type as the next node type we want to visit. So a single walk in our graph might look like this: `[app1, api1, method1, api2, package2, api3, app2]`. We repeat this process multiple times per app for each app in our graph.
 
**Step 2 - Word2vec)** We then treat each walk as a sentence with the nodes we visited being the words of this sentence. Combining all of the walks together, we now have a corpus of walks that we can feed into a word2vec model. This will return vector representations, also called *node embeddings*, of each app in our graph. But why word2vec, especially since it was originally meant for text data? With the walks we performed, we now have a text-like representation of our graph, so we are able to pass that into word2vec.
 
Using this process, we were able to generate the following plot of every app in our dataset. For the most part it seems that this method is able to distinguish between not only malware and non-malware, but can also distinguish between different classes of malware to a reasonable extent.
 
{% include 3D-plot.html %}

### Exploring the Plot
Looking at this plot, we seem to have multiple clusters of apps. We wanted to theorize why these clusters might be occurring  so we compiled descriptions of a few types of malware and some possible explanations for why we see what we see. 

- **BankBot:** a mobile banking trojan that steals banking credentials and payment information, by presenting an overlay window which looks identical to a bank app’s login page, 
- **RuMMs:** a distributed through SMS phishing, and in some cases initiate transactions by contacting financial institutions.
- **Simplelocker:** a ransomware that encrypts the users data, which includes a pop up window that requests a fee to recover data. 
- **Lotoor:** a trojan that tries to manage the data on the system and change the settings on the device.
- **FakeInst:** portrays itself as the real instagram app but will actually send premium SMS text messages once the user installs it. It evolved into many different variations over the years, so the numerous  clusters we see are likely due to the similar versions of it clustering together.

The two distinct BankBot and RuMMs clusters may be explained by them both targeting banking data, as RuMMs initiates transactions and BankBot steals a user’s banking information. Rumms and Bankbot are also both considered trojans. Then there is the general malware cluster defined mostly by the apps from the Other Malware category. What may be contributing to these apps clustering together is that they might share many of the common APIs used for carrying out general malicious activity such as privilege  elevation, data harvesting, opening pops, or modifying system files.

## ADVERSARIAL ATTACK
The goal for our adversarial attack to see if it was possible to attack HinDroid or our model through adversarial machine learning. To do this, we applied many of the techniques laid out in the paper Android HIV by Chen, et al. In it, they described how they attacked MamaDroid and Drebin, two other Android malware detectors, with great effectiveness all while keeping the malware functional. We modified one of the algorithms they used in order to fit our problem called the Carlini and Wagner L2 attack. We did this by modifying the constraints of their objective function as such:
 
$$
min_{\delta}\Vert\delta\Vert^2_2 + c \cdot f(X+\delta) \\
s.t. X + \delta \in \{0,1\}^n \\
\text{and } X_i + \delta_i \ne 1 \text{ if } X_i = 1
$$
 
where
 
$$
f(x') = \max\{0, (\max_{i \ne t}{Z(x')_i} - Z(x')_t) \cdot \tau + \kappa\}
$$
 
To explain, $min_{\delta}\Vert\delta\Vert^2_2 + c \cdot f(X+\delta)$ is the objective function trying to find a perturbations, $\delta$, we can add to the original example, $X$ so that the model misclassifies the resulting app. $X + \delta \in \{0,1\}^n$ simply ensures that we work with the discrete values 0 and 1, since the input to our model and HinDroid is a one-hot-encoded vector for the apps in our dataset. We also want to ensure that we do not remove any APIs from an app as it could likely break the app entirely. We want to avoid this just as the Android HIV authors did. This is covered by $X_i + \delta_i \ne 1 \text{ if } X_i = 1$.
 
In reality, it wasn't as simple as just changing this function. Working with the discrete one-hot values will not work natively with the C&W algorithm as it was originally constructed for continuous values. This made it straightforward for the Android HIV authors to modify it to work with the probability values, but it does not directly transfer to our problem. To solve this, we modified the *tanh-trick* used by the C&W attack to optimize the perturbations. The trick maps the values of the perturbations into an infinite space to make gradient descent more reliable when boundary constraints are applied (such as limiting the values to be in $[0,1]$). To perform the mapping, the values are scaled to the input range of the $\tanh^{-1}$ function or $[-1,1]$ and then passed through it. What we did was add a scalar $\lambda$ that scales this function dramatically to make the transition between 0 and 1 approximately instantaneous. This was the key to making the algorithm compatible with our discrete values. Of course, it was still possible for the perturbations to fall between 0 and 1, so we were sure to perform a validation step by rounding each example and getting the final output label using the rounded example.

## EXPERIMENTS
 
To evaluate our methods we conducted two tests: The first evaluating the performance of HinDroid vs m2vDroid and second evaluating the strength of our adversarial attack.
 
### HinDroid vs m2vDroid 
To test our models, we used a dataset of 6,451 apps. 5,516 of these apps have been deemed malicious through other methods. We will use this as the malware set. For the benign set, we selected 2 categories of apps: popular apps and random apps. Popular apps were selected from the popular category of [apkpure.com](https://apkpure.com/), an Android app repository. Random apps were selected at random from the site. While popular apps are unlikely to be malicious, the same could not be said for random apps. Some estimates believe that up to 5% of the apps could contain malware. Nevertheless, we use these apps to bolster the benign app set as not doing so would make the benign app set negligibly small compared to the malware set. In total, we used 905 apps for the benign set, with 324 popular apps and 581 random apps. We then created a training set with one third of the apps, with the remainder becoming the test set, being sure to keep the proportion of each category of apps equal. With these sets, we will compare the performance of m2vDroid against 5 of HinDroid's best performing single-kernel models ($AA^T$, $ABA^T$, $APA^T$, $ABPB^TA^T$, $APBP^TA^T$).
 
We can see that while we still achieved some respectable numbers, m2vDroid struggled to keep up with the HinDroid kernels' performances and it had a pronounced issue with false positives. This may simply be the case that m2vDroid is not as effective as HinDroid or that we may need to further tune the parameters of it. However, considering that some other kernels faced the same issue, albeit with a smaller magnitude, this may be the result of the heavy bias in our dataset. This could also be due to the inclusion of random apps. Recall that a small percentage of these apps may actually be malware but we may have mislabeled them as benign by assuming all random apps were benign to begin with. It may be worth the effort to perform the test again by either excluding random apps or filtering possible malware using another method.
 
|       |ACC               |TPR                 |F1                |TP                   |TN                 |FP |FN |
|-------|------------------|--------------------|------------------|---------------------|-------------------|---|---|
|**m2vDroid**| 0.950            | 1.000              | 0.973            | 3676                | 169               | 202| 1 |
|**AAT**| 0.986            | 0.999              | 0.992            | 3674                | 316               | 55| 3 |
|**ABAT**| 0.976            | 0.990              | 0.987            | 3642                | 310               | 61| 35|
|**APAT**| 0.979            | 0.998              | 0.989            | 3670                | 294               | 77| 7 |
|**ABPBTAT**| 0.986            | 0.999              | 0.992            | 3672                | 320               | 51| 5 |
|**APBPTAT**| 0.976            | 0.992              | 0.987            | 3647                | 303               | 68| 30|
 
### Evaluating the Adversarial Attack
We evaluated our attack by generating examples against a deep neural network substitute for the $AA^T$ HinDroid kernel. With the examples we generated using our modified C&W attack, we then tested how well these examples were at evading, not just original $AA^T$ kernel, but all HinDroid kernels. We were returned the following results.
 
|**Original AAT Label**|AAT               |ABAT                |APAT              |ABPBTAT              |APBPTAT            |Support|
|----------------------|------------------|--------------------|------------------|---------------------|-------------------|-------|
|**Benign**            | 80.0%            | 96.4%              | 58.2%            | 96.4%               | 5.5%              | 55    |
|**Malware**           | 99.3%            | 1.1%               | 99.1%            | 0.2%                | 99.3%             | 445   |
|**Total**             | 97.2%            | 11.6%              | 94.6%            | 10.8%               | 89.0%             | 500   |
 
Being that we trained against the $AA^T$ kernel for the test, it is not surprising we see that that the attack was most successful against this kernel, achieving a evasion rate of 97.2%. Malware examples were also able to evade the $APA^T$ and $APBP^TA^T$ kernels with a success rate >99%. Malware examples were fairly ineffective when it came to the $APA^T$ and $ABPB^TA^T$ kernels. It may be that these kernels are more broad with their definition of malware, making it harder for the malware examples to evade them. The inverse might be said for the $APBP^TA^T$ where benign examples struggled to evade the classifier. Overall, we believe these results are incredibly promising for our method and would like to expand them to other kernels as well as our model in the future.

## ACKNOWLEDGEMENTS
- Carlini, Nicholas, and David Wagner. “Towards Evaluating the Robustness of Neural Networks.”, doi:10.1109/sp.2017.49. 
- Chen, Xiao, et al. “Android HIV: A Study of Repackaging Malware for Evading Machine-Learning Detection.” IEEE Transactions on Information Forensics and Security, vol. 15, 2020, pp. 987–1001., doi:10.1109/tifs.2019.2932228. 
- Hou, Shifu, et al. “HinDroid: An Intelligent Android Malware Detection System Based on Structured Heterogeneous Information Network.” 2017, doi:10.1145/3097983.3098026.
- Dong, Yuxiao, et al. “metapath2vec: Scalable Representation Learning for Heterogeneous Networks.” 2017, doi:10.1145/3097983.3098036. 
- APKTool. http://ibotpeaches.github.io/Apktool/.
- Stellargraph. https://github.com/stellargraph/stellargraph
- Gensim. https://radimrehurek.com/gensim/
- PyTorch implementation of Carlini-Wanger's L2 attack. https://github.com/kkew3/pytorch-cw2
- Imbalanced Data Sampler by ufoym. https://github.com/ufoym/imbalanced-dataset-sampler

And to our mentors, Professor Aaron Fraenkel and Shivam Lakhotia, who provided guidance and insight throughout our project.


## APENDIX
- [Source code](https://github.com/rcgonzalez9061/m2v-adversarial-hindroid)
- [View our full report](https://rcgonzalez9061.github.io/m2vDroid-blog/report.pdf)
