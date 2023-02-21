use std::sync::Arc;
use std::time::Duration;

use mqtt_proto::v3::*;
use mqtt_proto::*;
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::config::Config;
use crate::state::GlobalState;
use crate::tests::utils::MockConn;

use super::{build_publish, ControlV3};

#[tokio::test]
async fn test_publish_qos0() {
    let global = Arc::new(GlobalState::new(
        "127.0.0.1:1883".parse().unwrap(),
        Config::new_allow_anonymous(),
    ));

    // publisher
    let (_task0, mut control0) = MockConn::start_with_global(100, Arc::clone(&global));

    // subscriber
    let (_task1, control1) = MockConn::start_with_global(111, Arc::clone(&global));
    let (_task2, control2) = MockConn::start_with_global(222, Arc::clone(&global));
    let (_task3, control3) = MockConn::start_with_global(333, Arc::clone(&global));
    let (_task4, control4) = MockConn::start_with_global(444, Arc::clone(&global));

    // Publisher connect
    control0.connect("publisher", true, false).await;

    let (tx, mut rx) = mpsc::channel(4);
    let mut tasks = Vec::new();
    for (topic, mut control) in [
        ("xyz/0", control1),
        ("xyz/+", control2),
        ("#", control3),
        // will not match
        ("xxx/bbb", control4),
    ] {
        let tx = tx.clone();
        let task = tokio::spawn(async move {
            control
                .connect(format!("subscriber: {}", topic), true, false)
                .await;
            control.subscribe(2, vec![(topic, QoS::Level0)]).await;

            // Subscribe is ready
            tx.send(()).await.unwrap();
            sleep(Duration::from_millis(100)).await;

            if topic != "xxx/bbb" {
                for last_byte in 0..14u8 {
                    control
                        .recv_publish(QoS::Level0, 0, "xyz/0", vec![3, 5, 55, last_byte], |_| ())
                        .await;
                }
            }
            sleep(Duration::from_millis(100)).await;
            assert!(control.try_read_packet_is_empty());
        });
        tasks.push(task);
    }

    // Wait 4 subscribers
    for _ in 0..4 {
        rx.recv().await.unwrap();
    }

    for last_byte in 0..14u8 {
        control0
            .send_publish(QoS::Level0, 0, "xyz/0", [3, 5, 55, last_byte], |_| ())
            .await;
    }
    sleep(Duration::from_millis(20)).await;
    assert!(control0.try_read_packet_is_empty());

    for task in tasks {
        assert!(task.await.is_ok());
    }
}

#[tokio::test]
async fn test_publish_qos1() {
    let global = Arc::new(GlobalState::new(
        "127.0.0.1:1883".parse().unwrap(),
        Config::new_allow_anonymous(),
    ));

    // publisher
    let (_task0, mut control0) = MockConn::start_with_global(100, Arc::clone(&global));

    // subscriber
    let (_task1, control1) = MockConn::start_with_global(111, Arc::clone(&global));
    let (_task2, control2) = MockConn::start_with_global(222, Arc::clone(&global));
    let (_task3, control3) = MockConn::start_with_global(333, Arc::clone(&global));
    let (_task4, control4) = MockConn::start_with_global(444, Arc::clone(&global));

    // Publisher connect
    control0.connect("publisher", true, false).await;

    let (tx, mut rx) = mpsc::channel(4);
    let mut tasks = Vec::new();
    for (topic, mut control) in [
        ("xyz/1", control1),
        ("xyz/+", control2),
        ("#", control3),
        // will not match
        ("xxx/bbb", control4),
    ] {
        let tx = tx.clone();
        let task = tokio::spawn(async move {
            control
                .connect(format!("subscriber: {}", topic), true, false)
                .await;
            control.subscribe(2, vec![(topic, QoS::Level1)]).await;

            // Subscribe is ready
            tx.send(()).await.unwrap();

            sleep(Duration::from_millis(100)).await;

            if topic != "xxx/bbb" {
                for pub_pid in 1..15u16 {
                    control
                        .recv_publish(
                            QoS::Level1,
                            pub_pid,
                            "xyz/1",
                            vec![3, 5, 55, pub_pid as u8],
                            |_| (),
                        )
                        .await;
                    control.send_puback(pub_pid).await;
                }
            }
            sleep(Duration::from_millis(100)).await;
            assert!(control.try_read_packet_is_empty());
        });
        tasks.push(task);
    }

    // Wait 4 subscribers
    for _ in 0..4 {
        rx.recv().await.unwrap();
    }

    for pub_pid in 1..15u16 {
        control0
            .publish(
                QoS::Level1,
                pub_pid,
                "xyz/1",
                [3, 5, 55, pub_pid as u8],
                |_| (),
            )
            .await;
    }

    sleep(Duration::from_millis(20)).await;
    assert!(control0.try_read_packet_is_empty());

    for task in tasks {
        assert!(task.await.is_ok());
    }
}

#[tokio::test]
async fn test_publish_qos2() {
    let global = Arc::new(GlobalState::new(
        "127.0.0.1:1883".parse().unwrap(),
        Config::new_allow_anonymous(),
    ));

    // publisher
    let (_task0, mut control0) = MockConn::start_with_global(100, Arc::clone(&global));

    // subscriber
    let (_task1, control1) = MockConn::start_with_global(111, Arc::clone(&global));
    let (_task2, control2) = MockConn::start_with_global(222, Arc::clone(&global));
    let (_task3, control3) = MockConn::start_with_global(333, Arc::clone(&global));
    let (_task4, control4) = MockConn::start_with_global(444, Arc::clone(&global));

    // Publisher connect
    control0.connect("publisher", true, false).await;

    let (tx, mut rx) = mpsc::channel(4);
    let mut tasks = Vec::new();
    for (topic, mut control) in [
        ("xyz/2", control1),
        ("xyz/+", control2),
        ("#", control3),
        // will not match
        ("xxx/bbb", control4),
    ] {
        let tx = tx.clone();
        let task = tokio::spawn(async move {
            control
                .connect(format!("subscriber: {}", topic), true, false)
                .await;
            control.subscribe(2, vec![(topic, QoS::Level2)]).await;

            // Subscribe is ready
            tx.send(()).await.unwrap();

            sleep(Duration::from_millis(100)).await;

            if topic != "xxx/bbb" {
                let mut pub_pid = 1;
                let mut rel_pid = 1;
                while pub_pid < 15 || rel_pid < 15 {
                    let packet = control.read_packet().await;
                    match packet {
                        Packet::Publish(publish) => {
                            let expected = build_publish(
                                QoS::Level2,
                                pub_pid,
                                "xyz/2",
                                vec![3, 5, 55, pub_pid as u8],
                                |_| (),
                            );
                            assert_eq!(publish, expected);
                            control.send_pubrec(pub_pid).await;
                            pub_pid += 1;
                        }
                        Packet::Pubrel(pid) => {
                            assert_eq!(pid.value(), rel_pid);
                            control.send_pubcomp(rel_pid).await;
                            rel_pid += 1;
                        }
                        pkt => panic!("invalid packet from server: {:?}", pkt),
                    }
                }
            }
            sleep(Duration::from_millis(100)).await;
            assert!(control.try_read_packet_is_empty());
        });
        tasks.push(task);
    }

    // Wait 4 subscribers
    for _ in 0..4 {
        rx.recv().await.unwrap();
    }

    for pub_pid in 1..15u16 {
        control0
            .publish(
                QoS::Level2,
                pub_pid,
                "xyz/2",
                vec![3, 5, 55, pub_pid as u8],
                |_| (),
            )
            .await;
    }

    sleep(Duration::from_millis(20)).await;
    assert!(control0.try_read_packet_is_empty());

    for task in tasks {
        assert!(task.await.is_ok());
    }
}
