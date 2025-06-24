package org.example.fabric;


import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import io.grpc.ChannelCredentials;
import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.TlsChannelCredentials;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;

import org.hyperledger.fabric.client.*;
import org.hyperledger.fabric.client.identity.Identities;
import org.hyperledger.fabric.client.identity.Identity;
import org.hyperledger.fabric.client.identity.Signer;
import org.hyperledger.fabric.client.identity.Signers;
import org.hyperledger.fabric.client.identity.X509Identity;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.annotations.XYTitleAnnotation;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.axis.NumberTickUnit;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.ValueMarker;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.chart.title.LegendTitle;
import org.jfree.chart.ui.*;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public final class Example {
    public static void main(final String[] args)
            throws IOException, CertificateException, InvalidKeyException, GatewayException, CommitException,
            InterruptedException {
        // Create client identity based on X.509 certificate.
        Reader certReader = Files.newBufferedReader(Paths.get("src/main/resources/org1.example.com/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem"));
        X509Certificate certificate = Identities.readX509Certificate(certReader);
        Identity identity = new X509Identity("Org1MSP", certificate);

        // Create signing implementation based on private key.
        Reader keyReader = Files.newBufferedReader(Paths.get("src/main/resources/org1.example.com/users/User1@org1.example.com/msp/keystore/priv_sk"));
        PrivateKey privateKey = Identities.readPrivateKey(keyReader);
        Signer signer = Signers.newPrivateKeySigner(privateKey);

        // Create gRPC client connection, which should be shared by all gateway connections to this endpoint.
        ChannelCredentials tlsCredentials = TlsChannelCredentials.newBuilder()
                .trustManager(Paths.get("src/main/resources/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt").toFile())
                .build();
        ManagedChannel grpcChannel = Grpc.newChannelBuilder("129.28.92.157:7051", tlsCredentials)
                .overrideAuthority("peer0.org1.example.com")
                .build();
//        ManagedChannel channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();

        // Create a Gateway connection for a specific client identity.
        Gateway.Builder builder = Gateway.newInstance()
                .identity(identity)
                .signer(signer)
                .hash(Hash.SHA256)
                .connection(grpcChannel);
        Example aa= new Example();
        try (Gateway gateway = builder.connect()) {
            // Obtain smart contract deployed on the network.
            Network network = gateway.getNetwork("mychannel");
            Contract contract = network.getContract("basic");
            var result = contract.getChaincodeName();
            System.out.println(result);
            System.out.println(contract.getContractName());
            aa.run(contract);


        } finally {
            grpcChannel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }

    }
    public void run(Contract con) throws GatewayException, CommitException {
//        String jsonString = "{\n" +
//                "  \"@context\": \"https://www.w3.org/ns/did/v1\",\n" +
//                "  \"id\": \"did:hedera:testnet:432Cw4mfERxXHKAAJcRa8aBuhHmCaBAhZLvCnfYZPrPS;hedera:testnet:fid=0.0.24353\",\n" +
//                "  \"publicKey\": [\n" +
//                "    {\n" +
//                "      \"id\": \"did:hedera:testnet:432Cw4mfERxXHKAAJcRa8aBuhHmCaBAhZLvCnfYZPrPS;hedera:testnet:fid=0.0.24353#did-root-key\",\n" +
//                "      \"type\": \"Ed25519VerificationKey2018\",\n" +
//                "      \"controller\": \"did:hedera:testnet:432Cw4mfERxXHKAAJcRa8aBuhHmCaBAhZLvCnfYZPrPS;hedera:testnet:fid=0.0.24353\",\n" +
//                "      \"publicKeyBase58\": \"3fmHJkLMmcxLUUcY7jFfJ9Lhc6mVrZDHjutMBmFsDhoK\"\n" +
//                "    }\n" +
//                "  ],\n" +
//                "  \"authentication\": [\n" +
//                "    \"did:hedera:testnet:432Cw4mfERxXHKAAJcRa8aBuhHmCaBAhZLvCnfYZPrPS;hedera:testnet:fid=0.0.24353#did-root-key\"\n" +
//                "  ]\n" +
//                "}\n";
//
//        con.submitTransaction("CreateAsset", "fabric", jsonString, "5", "Tom", "1300");


        System.out.println("\n--> Evaluate Transaction: GetAllAssets, function returns all the current assets on the ledger");

//        var result = con.evaluateTransaction("GetAllAssets");
//
//        System.out.println("*** Result: " + prettyJson(result));

        List<Double> queryTimes = new ArrayList<>();
        for (int i = 0; i < 101; i++) {
            long startTime = System.nanoTime();
            var evaluateResult = con.evaluateTransaction("ReadAsset", "fabric");
            long endTime = System.nanoTime();
            double duration = (endTime - startTime) / 1_000_000.0; // Convert to milliseconds
            queryTimes.add(duration);
            System.out.println("*** Result:" + evaluateResult);
        }

        // Generate line chart，第一次需要建立通讯，因此减去第一次的时间
        XYSeries series = new XYSeries("Query Time");
        //计算总时间
        double total = 0;

        for (int i = 1; i < queryTimes.size(); i++) {
            series.add(i, queryTimes.get(i));
            System.out.println("第"+i+"次查询时间："+queryTimes.get(i)+"ms");
            total += queryTimes.get(i);
        }
        double avgTime = total / 100;
        System.out.println("avg time: " + avgTime);
        XYSeriesCollection dataset = new XYSeriesCollection(series);

        JFreeChart chart = ChartFactory.createXYLineChart(
                "",
                "Number of accesses on the blockchain",
                "Time (ms)",
                dataset,
                PlotOrientation.VERTICAL,
                true, true, false);

        XYPlot plot = chart.getXYPlot();
        XYLineAndShapeRenderer renderer = new XYLineAndShapeRenderer();
        // Set the color of the line
        plot.setRenderer(renderer);

        // Remove background and grid lines
        plot.setBackgroundPaint(Color.WHITE);
        plot.setDomainGridlinesVisible(false);
        plot.setRangeGridlinesVisible(false);

        NumberAxis domainAxis = (NumberAxis) plot.getDomainAxis();
        domainAxis.setTickUnit(new NumberTickUnit(20));
        domainAxis.setTickLabelFont(new Font("Times New Roman", Font.PLAIN, 8));

        // Add average time marker
        ValueMarker avgMarker = new ValueMarker(avgTime);
        avgMarker.setPaint(Color.RED);
        avgMarker.setStroke(new BasicStroke(2.0f, BasicStroke.CAP_BUTT, BasicStroke.JOIN_BEVEL, 0, new float[]{10.0f}, 0));
        avgMarker.setLabel("Average Time");
        avgMarker.setLabelAnchor(RectangleAnchor.TOP_LEFT);
        avgMarker.setLabelTextAnchor(TextAnchor.BOTTOM_LEFT);
        // Add the average time marker to the plot
        plot.addRangeMarker(avgMarker);

        // Add legend inside the chart
        LegendTitle legend = chart.getLegend();
        legend.setPosition(RectangleEdge.BOTTOM);
        legend.setHorizontalAlignment(HorizontalAlignment.CENTER);
        legend.setVerticalAlignment(VerticalAlignment.BOTTOM);
        plot.addAnnotation(new XYTitleAnnotation(0.95, 0.95, legend, RectangleAnchor.BOTTOM_RIGHT));

        ChartPanel chartPanel = new ChartPanel(chart);
        chartPanel.setPreferredSize(new Dimension(800, 600));

        JFrame frame = new JFrame("Query Time Chart Example");
        frame.setContentPane(chartPanel);
        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        frame.setVisible(true);
    }

    private String prettyJson(final byte[] json) {
        return prettyJson(new String(json, StandardCharsets.UTF_8));
    }
    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private String prettyJson(final String json) {
        var parsedJson = JsonParser.parseString(json);
        return gson.toJson(parsedJson);
    }

}
